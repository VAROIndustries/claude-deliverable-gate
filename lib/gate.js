'use strict'
// Orchestration: candidates, reports, approvals, publication, retention. All state lives under the gate home,
// never in the source workspace.
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { sha256, canonical, deliverableDir, readJson, writeJson, safe, UsageError, rmTree, home } = require('./util')
const { validatePolicy, buildSnapshot, CHECK_IDS } = require('./snapshot')
const checks = require('./checks')
const { checkDestination, publishSnapshot, identity, remoteUrl, identityGuard } = require('./destination')

class Refusal extends Error {}

const policyFile = (name) => path.join(deliverableDir(name), 'policy.json')
const candDir = (name, id) => {
  if (!/^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$/.test(id || '')) throw new UsageError(`invalid candidate id: ${JSON.stringify(id)}`)
  return path.join(deliverableDir(name), 'candidates', id)
}
const approvalFile = (name, id) => path.join(deliverableDir(name), 'approvals', `${id}.json`)

function loadPolicy(name) {
  const f = policyFile(name)
  if (!fs.existsSync(f)) throw new UsageError(`no policy for "${name}". Create one with: gate.js init ${name} --repo <path>`)
  const raw = readJson(f)
  const policy = validatePolicy(raw)
  if (policy.name !== name) throw new UsageError(`policy name "${policy.name}" does not match deliverable "${name}"`)
  return { policy, policyHash: sha256(canonical(raw)) }
}

const candidateHash = (files) => sha256(files.map((f) => `${f.mode} ${f.sha256} ${f.size} ${f.path}\n`).join(''))

function init(name, repo) {
  const f = policyFile(name)
  if (fs.existsSync(f)) throw new UsageError(`policy already exists: ${f}`)
  const p = readJson(path.join(__dirname, '..', 'examples', 'policy.example.json'))
  p.name = name
  p.source.repo = path.resolve(repo).split(path.sep).join('/')
  writeJson(f, p)
  return f
}

function newId() {
  const t = new Date().toISOString()
  return `${t.slice(0, 10).replace(/-/g, '')}-${t.slice(11, 19).replace(/:/g, '')}-${crypto.randomBytes(2).toString('hex')}`
}

function latestApproval(name) {
  const dir = path.join(deliverableDir(name), 'approvals')
  if (!fs.existsSync(dir)) return null
  const all = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => readJson(path.join(dir, f)))
  return all.sort((a, b) => (a.approvedAt < b.approvedAt ? -1 : 1)).pop() || null
}

function diffManifests(prev, files) {
  const before = new Map(prev.files.map((f) => [f.path, f.sha256]))
  const now = new Map(files.map((f) => [f.path, f.sha256]))
  return {
    against: prev.candidateId,
    added: [...now.keys()].filter((p) => !before.has(p)),
    removed: [...before.keys()].filter((p) => !now.has(p)),
    modified: [...now.keys()].filter((p) => before.has(p) && before.get(p) !== now.get(p)),
  }
}

function check(name, opts = {}) {
  const { policy, policyHash } = loadPolicy(name)
  const id = newId()
  const dir = candDir(name, id)
  fs.mkdirSync(dir, { recursive: true })
  const snap = buildSnapshot(policy, dir)
  const dest = checkDestination(policy, opts)
  const manifest = {
    deliverable: name,
    candidateId: id,
    createdAt: new Date().toISOString(),
    candidateHash: candidateHash(snap.files),
    policyHash,
    mode: policy.mode,
    audience: policy.audience || null,
    destination: dest.identity,
    source: snap.source,
    totals: { files: snap.files.length, bytes: snap.files.reduce((n, f) => n + f.size, 0), excluded: snap.excluded.length },
    files: snap.files,
    excluded: snap.excluded,
  }
  writeJson(path.join(dir, 'manifest.json'), manifest)

  const filesDir = path.join(dir, 'files')
  const ctx = {
    policy, opts, candDir: dir, files: snap.files, excluded: snap.excluded, source: snap.source, read: snap.read,
    snapshotFindings: snap.findings,
    readCandidate: (rel) => fs.readFileSync(path.join(filesDir, ...rel.split('/'))),
  }
  const results = {}
  for (const c of CHECK_IDS) {
    try {
      results[c] = c === 'destination' ? { status: dest.status, summary: dest.summary, findings: dest.findings, head: dest.head } : checks[c](ctx)
    } catch (e) {
      results[c] = { status: 'INCOMPLETE', summary: `check errored: ${safe(e.message)}`, findings: [] }
    }
    results[c].required = policy.requiredChecks.includes(c)
  }
  const req = Object.entries(results).filter(([, r]) => r.required)
  const verdict = req.some(([, r]) => r.status === 'FAIL') ? 'BLOCKED' : req.some(([, r]) => r.status === 'INCOMPLETE') ? 'INCOMPLETE' : 'READY'
  const prev = latestApproval(name)
  let changes = null
  if (prev && fs.existsSync(path.join(candDir(name, prev.candidateId), 'manifest.json'))) changes = diffManifests(readJson(path.join(candDir(name, prev.candidateId), 'manifest.json')), snap.files)
  else if (prev) changes = { against: prev.candidateId, unavailable: 'previous approved manifest was cleaned up' }

  const report = { deliverable: name, candidateId: id, candidateHash: manifest.candidateHash, policyHash, verdict, destination: dest.identity, checks: results, changes, generatedAt: manifest.createdAt }
  writeJson(path.join(dir, 'report.json'), report)
  const md = renderReport(manifest, report)
  fs.writeFileSync(path.join(dir, 'report.md'), md)
  return { id, verdict, report, md, dir }
}

function renderReport(m, r) {
  const L = []
  const s = m.source
  L.push(`# Deliverable Gate report: ${safe(m.deliverable)}`, '')
  L.push(`- **Candidate:** \`${m.candidateId}\` (sha256 \`${m.candidateHash.slice(0, 16)}…\`)`)
  L.push(`- **Destination:** \`${safe(m.destination)}\``)
  L.push(`- **Audience:** ${safe(m.audience || '(not stated)')}`)
  L.push(`- **Mode:** ${m.mode}`)
  L.push(`- **Source:** \`${safe(s.repo)}\`${s.base ? ` (base \`${safe(s.base)}\`)` : ''} at \`${s.revision.slice(0, 12)}\` (${s.revisionSpec})`)
  L.push(`- **Working tree:** ${s.dirty ? `dirty, ${s.changedPaths} changed/untracked path(s); ${s.uncommittedChangesNotIncluded} of them are NOT in the candidate (it is built from the commit${s.worktreePaths.length ? ' plus opted-in worktree paths' : ''})` : 'clean'}`)
  L.push(`- **Totals:** ${m.totals.files} file(s), ${m.totals.bytes} bytes included; ${m.totals.excluded} excluded`, '')
  L.push(`## Verdict: ${r.verdict}`, '')
  L.push({ READY: 'Every required check passed. Approval may be requested.', INCOMPLETE: 'No required check failed, but some could not be completed. Approval requires explicitly accepting each incomplete check.', BLOCKED: 'At least one required check failed. This candidate cannot be approved.' }[r.verdict], '')
  L.push('| Check | Required | Result | Summary |', '| --- | --- | --- | --- |')
  for (const [id, c] of Object.entries(r.checks)) L.push(`| ${id} | ${c.required ? 'yes' : 'advisory'} | **${c.status}** | ${safe(c.summary)} |`)
  L.push('')
  const withFindings = Object.entries(r.checks).filter(([, c]) => c.findings?.length)
  if (withFindings.length) {
    L.push('## Findings', '', '_File names and locations only. Matched text is never reproduced._', '')
    for (const [id, c] of withFindings) {
      L.push(`### ${id}: ${c.status}`, '')
      for (const f of c.findings) L.push(`- ${f.file ? `\`${safe(f.file)}${f.line ? ':' + f.line : ''}\`` : ''}${f.target ? ` → \`${safe(f.target)}\`` : ''}${f.rule ? ` [${safe(f.rule)}]` : ''} ${safe(f.message || '')}`.replace(/^- +/, '- '))
      L.push('')
    }
  }
  const waived = r.checks.sensitive?.waived || []
  if (waived.length) {
    L.push('### Waived by policy', '')
    for (const w of waived) L.push(`- \`${safe(w.file)}\` [${safe(w.rule)}]: ${safe(w.reason)}`)
    L.push('')
  }
  if (r.changes) {
    L.push(`## Changes since last approved candidate \`${r.changes.against}\``, '')
    if (r.changes.unavailable) L.push(`_${r.changes.unavailable}._`)
    else {
      for (const k of ['added', 'removed', 'modified']) L.push(`- **${k}** (${r.changes[k].length}): ${r.changes[k].map((p) => `\`${safe(p)}\``).join(', ') || 'none'}`)
    }
    L.push('')
  } else L.push('## Changes since last approved candidate', '', '_No previous approval: everything is new._', '')
  L.push(`## Included files (${m.files.length})`, '', '| Path | Size | SHA-256 | From | Note |', '| --- | ---: | --- | --- | --- |')
  for (const f of m.files) L.push(`| \`${safe(f.path)}\` | ${f.size} | \`${f.sha256.slice(0, 12)}\` | ${f.source} | ${f.worktreeDiffers ? 'working copy differs; committed version used' : ''}${f.mode === '100755' ? ' executable' : ''} |`)
  L.push('', `## Excluded files (${m.excluded.length})`, '')
  if (m.excluded.length) {
    L.push('| Path | Reason |', '| --- | --- |')
    for (const e of m.excluded.slice(0, 500)) L.push(`| \`${safe(e.path)}\` | ${safe(e.reason)} |`)
    if (m.excluded.length > 500) L.push(`| … | ${m.excluded.length - 500} more in manifest.json |`)
  } else L.push('_None._')
  L.push('', '---', '', 'Passing checks reduce risk; they do not guarantee the deliverable contains no confidential information. INCOMPLETE means not checked, never safe.', '')
  return L.join('\n')
}

// Recompute the candidate from the snapshot on disk and compare with its manifest.
function verifyCandidate(name, id) {
  const dir = candDir(name, id)
  if (!fs.existsSync(path.join(dir, 'manifest.json'))) throw new Refusal(`candidate ${id} not found (cleaned up?)`)
  const m = readJson(path.join(dir, 'manifest.json'))
  const filesDir = path.join(dir, 'files')
  const problems = []
  const onDisk = fs.existsSync(filesDir) ? fs.readdirSync(filesDir, { recursive: true, withFileTypes: true }).filter((e) => !e.isDirectory()).map((e) => path.relative(filesDir, path.join(e.parentPath ?? e.path, e.name)).split(path.sep).join('/')) : []
  const want = new Map(m.files.map((f) => [f.path, f]))
  for (const p of onDisk) if (!want.has(p)) problems.push(`unexpected file in snapshot: ${p}`)
  for (const f of m.files) {
    const abs = path.join(filesDir, ...f.path.split('/'))
    let st
    try { st = fs.lstatSync(abs) } catch { problems.push(`missing from snapshot: ${f.path}`); continue }
    if (!st.isFile()) { problems.push(`not a regular file: ${f.path}`); continue }
    if (sha256(fs.readFileSync(abs)) !== f.sha256) problems.push(`modified since check: ${f.path}`)
  }
  if (candidateHash(m.files) !== m.candidateHash) problems.push('manifest file list does not match its candidate hash')
  return { manifest: m, problems }
}

const approvalHashOf = (a) => sha256(canonical({ ...a, approvedAt: undefined, approvalHash: undefined }))

function approve(name, id, { destination, acceptIncomplete = [] } = {}) {
  const { policy, policyHash } = loadPolicy(name)
  const { manifest, problems } = verifyCandidate(name, id)
  if (problems.length) throw new Refusal(`candidate changed after check:\n  ${problems.join('\n  ')}`)
  const report = readJson(path.join(candDir(name, id), 'report.json'))
  if (manifest.policyHash !== policyHash) throw new Refusal('policy changed since this candidate was checked; run check again')
  if (identity(policy.destination) !== manifest.destination) throw new Refusal('destination in policy differs from the checked candidate; run check again')
  if (destination !== manifest.destination) throw new Refusal(`--destination must restate the exact destination:\n  ${manifest.destination}`)
  const failed = [], incomplete = []
  for (const [c, r] of Object.entries(report.checks)) {
    if (!r.required) continue
    if (r.status === 'FAIL') failed.push(c)
    if (r.status === 'INCOMPLETE') incomplete.push(c)
  }
  if (failed.length) throw new Refusal(`required check(s) FAILED: ${failed.join(', ')}. Fix the source or policy and run check again.`)
  if (report.checks.destination.status !== 'PASS') throw new Refusal('the destination check must PASS; it cannot be accepted as incomplete')
  const unaccepted = incomplete.filter((c) => !acceptIncomplete.includes(c))
  if (unaccepted.length) throw new Refusal(`required check(s) INCOMPLETE: ${unaccepted.join(', ')}. Only the user may accept these, with --accept-incomplete ${unaccepted.join(',')}`)
  const a = {
    deliverable: name,
    candidateId: id,
    candidateHash: manifest.candidateHash,
    policyHash,
    destination: manifest.destination,
    destinationHead: report.checks.destination.head ?? null,
    sourceRevision: manifest.source.revision,
    acceptedIncomplete: incomplete,
    approvedAt: new Date().toISOString(),
  }
  a.approvalHash = approvalHashOf(a)
  writeJson(approvalFile(name, id), a)
  return a
}

function publish(name, id, opts = {}) {
  const { policy, policyHash } = loadPolicy(name)
  const f = approvalFile(name, id)
  if (!fs.existsSync(f)) throw new Refusal(`candidate ${id} is not approved; nothing published`)
  const a = readJson(f)
  if (approvalHashOf(a) !== a.approvalHash) throw new Refusal('approval record was altered; approve again')
  const { manifest, problems } = verifyCandidate(name, id)
  if (problems.length) throw new Refusal(`approval invalid, candidate changed after approval:\n  ${problems.join('\n  ')}`)
  if (manifest.candidateHash !== a.candidateHash) throw new Refusal('approval invalid: candidate hash differs from the approved one')
  if (policyHash !== a.policyHash) throw new Refusal('approval invalid: policy changed since approval')
  if (identity(policy.destination) !== a.destination) throw new Refusal('approval invalid: destination changed since approval')
  if (policy.mode !== 'snapshot') throw new Refusal('only snapshot publication is supported')
  if (!manifest.files.length) throw new Refusal('candidate is empty')
  const live = checkDestination(policy, opts)
  if (live.status !== 'PASS') throw new Refusal(`destination check no longer passes: ${live.summary} ${live.findings.map((x) => x.message).join(' ')}`)
  if ((live.head ?? null) !== a.destinationHead) throw new Refusal(`approval invalid: destination branch moved since approval (${a.destinationHead || 'absent'} -> ${live.head || 'absent'})`)
  const url = opts.remoteUrl || remoteUrl(policy.destination)
  const ig = opts.identityGuard === false ? { status: 'SKIPPED', summary: 'Identity Guard skipped' } : identityGuard(policy, url)
  if (ig.status === 'FAIL') throw new Refusal('Identity Guard reports an identity MISMATCH for this push; nothing published')
  const workDir = path.join(home(), 'work', `${name}-${id}`)
  try {
    const res = publishSnapshot({ policy, candDir: candDir(name, id), manifest, approval: a, workDir, opts })
    const rec = { deliverable: name, candidateId: id, candidateHash: a.candidateHash, approvalHash: a.approvalHash, destination: a.destination, ...res, identityGuard: ig.status, publishedAt: new Date().toISOString() }
    fs.appendFileSync(path.join(deliverableDir(name), 'publications.jsonl'), JSON.stringify(rec) + '\n')
    return { ...rec, identityGuardSummary: ig.summary }
  } finally {
    rmTree(workDir)
  }
}

function status(name) {
  const dir = deliverableDir(name)
  const { policy, policyHash } = loadPolicy(name)
  const cdir = path.join(dir, 'candidates')
  const rows = (fs.existsSync(cdir) ? fs.readdirSync(cdir) : []).sort().map((id) => {
    const rf = path.join(cdir, id, 'report.json')
    const r = fs.existsSync(rf) ? readJson(rf) : null
    let approval = null
    if (fs.existsSync(approvalFile(name, id))) {
      const a = readJson(approvalFile(name, id))
      const { problems } = verifyCandidate(name, id)
      const why = [problems.length && 'candidate changed', a.policyHash !== policyHash && 'policy changed', a.destination !== identity(policy.destination) && 'destination changed'].filter(Boolean)
      approval = why.length ? `INVALID (${why.join(', ')})` : `approved ${a.approvedAt}`
    }
    return { id, verdict: r?.verdict || 'unknown', approval }
  })
  const pf = path.join(dir, 'publications.jsonl')
  const pubs = fs.existsSync(pf) ? fs.readFileSync(pf, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []
  return { deliverable: name, destination: identity(policy.destination), policyFile: policyFile(name), candidates: rows, publications: pubs }
}

function list() {
  const d = path.join(home(), 'deliverables')
  return fs.existsSync(d) ? fs.readdirSync(d).filter((n) => fs.existsSync(path.join(d, n, 'policy.json'))) : []
}

// Retention: keep the newest `keep` candidates and the latest approved one; --all keeps only policy + publication log.
function clean(name, { keep = 3, all = false } = {}) {
  const dir = deliverableDir(name)
  const cdir = path.join(dir, 'candidates')
  const ids = fs.existsSync(cdir) ? fs.readdirSync(cdir).sort() : []
  const latest = latestApproval(name)?.candidateId
  const doomed = all ? ids : ids.slice(0, Math.max(0, ids.length - keep)).filter((id) => id !== latest)
  for (const id of doomed) {
    rmTree(path.join(cdir, id))
    fs.rmSync(approvalFile(name, id), { force: true })
  }
  if (all) rmTree(path.join(dir, 'approvals'))
  return { removed: doomed, kept: ids.filter((i) => !doomed.includes(i)) }
}

module.exports = { init, check, approve, publish, status, list, clean, verifyCandidate, loadPolicy, renderReport, Refusal }
