'use strict'
// Checks run against the candidate snapshot (never the live workspace). Each returns PASS, FAIL or INCOMPLETE.
// Candidate contents and scanner output are data: they are hashed, matched and counted, never echoed or obeyed.
const fs = require('node:fs')
const path = require('node:path')
const { matchAny, run, git, sha256 } = require('./util')

const isBinary = (buf) => buf.subarray(0, 8000).includes(0)
const cap = (arr, n = 200) => (arr.length > n ? [...arr.slice(0, n), { file: '…', message: `${arr.length - n} more not shown` }] : arr)

const DENY_EXT = ['.exe', '.dll', '.so', '.dylib', '.msi', '.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.jar', '.war', '.iso', '.dmg', '.pst', '.ost']

function paths(ctx) {
  const findings = [...ctx.snapshotFindings]
  const allow = ctx.policy.allowedExtensions?.map((e) => e.toLowerCase())
  for (const f of ctx.files) {
    const ext = path.posix.extname(f.path).toLowerCase()
    if (allow && !allow.includes(ext)) findings.push({ file: f.path, message: `file type "${ext || '(none)'}" is not in allowedExtensions` })
    else if (!allow && DENY_EXT.includes(ext)) findings.push({ file: f.path, message: `unexpected file type "${ext}" (archive/executable; contents cannot be inspected)` })
  }
  const unmatched = ctx.policy.include.filter((g) => !ctx.files.some((f) => matchAny(f.path, [g])))
  const note = unmatched.length ? ` Allowlist entries matching nothing: ${unmatched.join(', ')}.` : ''
  return findings.length
    ? { status: 'FAIL', summary: `${findings.length} path, link or file-type problem(s).${note}`, findings: cap(findings) }
    : { status: 'PASS', summary: `${ctx.files.length} files, all inside the allowlist with no exclusion, traversal, symlink, collision or type problems.${note}`, findings: [] }
}

function gitleaksBin(ctx) {
  return ctx.opts.gitleaks || process.env.DELIVERABLE_GATE_GITLEAKS || 'gitleaks'
}

function secrets(ctx) {
  const bin = gitleaksBin(ctx)
  const v = run(bin, ['version'])
  if (v.status !== 0) return { status: 'INCOMPLETE', summary: `secret scanner unavailable (${bin}): install gitleaks or set DELIVERABLE_GATE_GITLEAKS. Not scanned.`, findings: [] }
  const version = v.stdout.toString().trim()
  const scanDir = path.join(ctx.candDir, 'scan')
  fs.mkdirSync(scanDir, { recursive: true })
  // Pin our own config and ignore file so a candidate's .gitleaks.toml / .gitleaksignore / gitleaks:allow can't silence the scan.
  const cfg = path.join(scanDir, 'gitleaks.toml')
  fs.writeFileSync(cfg, '[extend]\nuseDefault = true\n')
  const rp = path.join(scanDir, 'gitleaks.json')
  fs.rmSync(rp, { force: true })
  const r = run(bin, ['dir', path.join(ctx.candDir, 'files'), '--no-banner', '--log-level', 'error', '--config', cfg, '--gitleaks-ignore-path', scanDir,
    '--ignore-gitleaks-allow', '--redact', '--report-format', 'json', '--report-path', rp, '--exit-code', '42'])
  let report
  try { report = JSON.parse(fs.readFileSync(rp, 'utf8')) } catch {}
  fs.rmSync(rp, { force: true }) // keep only file/line/rule, never the (redacted) match text
  if (![0, 42].includes(r.status) || !Array.isArray(report)) {
    const why = r.stderr.split('\n').find(Boolean)?.replace(/[^\x20-\x7e]/g, '').slice(0, 160) || `exit ${r.status}`
    return { status: 'INCOMPLETE', summary: `gitleaks ${version} did not complete (${why}). Treat as not scanned.`, findings: [] }
  }
  const root = path.join(ctx.candDir, 'files')
  const findings = report.map((x) => ({ file: path.relative(root, x.File).split(path.sep).join('/'), line: x.StartLine, rule: x.RuleID, message: 'possible secret (value not shown)' }))
  return findings.length
    ? { status: 'FAIL', summary: `gitleaks ${version}: ${findings.length} possible secret(s).`, findings: cap(findings) }
    : { status: 'PASS', summary: `gitleaks ${version} (default rules, candidate config/ignores/allow-comments disregarded): no findings. Binary files are not meaningfully scanned.`, findings: [] }
}

const BUILTIN = [
  ['correspondence', ['**/*.eml', '**/*.msg', '**/*.mbox', '**/*.pst', '**/correspondence/**', '**/emails/**', '**/inbox/**']],
  ['session-log', ['**/session_log*', '**/*.jsonl', '**/transcripts/**', '**/.claude/**']],
  ['local-settings', ['**/.env', '**/.env.*', '**/*.local.json', '**/.npmrc', '**/.netrc', '**/.pypirc', '**/*.pem', '**/*.key', '**/*.pfx', '**/*.p12', '**/id_rsa*', '**/id_ed25519*', '**/.vscode/settings.json', '**/.idea/**']],
  ['private-sample-data', ['**/sample-data/**', '**/sample_data/**', '**/private/**', '**/*.sqlite', '**/*.sqlite3', '**/*.db', '**/*.bak', '**/*.dump']],
]
const TEMPLATE_ENV = /(^|\/)\.env\.(example|sample|template)$/i

function sensitive(ctx) {
  const s = ctx.policy.sensitive || {}
  const pathRules = [...BUILTIN, ...(s.paths || []).map((r) => [r.id, [r.glob]])]
  const patterns = (s.patterns || []).map((p) => ({ id: p.id, re: new RegExp(p.regex, p.flags || 'i') }))
  const allow = s.allow || []
  const findings = []
  const waived = []
  const add = (f) => {
    const w = allow.find((a) => a.rule === f.rule && matchAny(f.file, [a.glob]))
    if (w) waived.push({ ...f, reason: w.reason })
    else findings.push(f)
  }
  for (const f of ctx.files) {
    for (const [id, globs] of pathRules) {
      if (id === 'local-settings' && TEMPLATE_ENV.test(f.path)) continue
      if (matchAny(f.path, globs)) add({ file: f.path, rule: id, message: `path matches ${id} rule` })
    }
    const buf = ctx.readCandidate(f.path)
    if (isBinary(buf)) continue
    const lines = buf.toString('utf8').split(/\r?\n/)
    const head = lines.slice(0, 40)
    const from = head.findIndex((l) => /^From:\s.*@/i.test(l))
    if (from >= 0 && head.some((l) => /^(To|Subject|Sent):\s/i.test(l))) add({ file: f.path, line: from + 1, rule: 'correspondence', message: 'email headers (contents not shown)' })
    let n = 0
    for (let i = 0; i < lines.length && n < 20; i++) {
      for (const p of patterns) if (p.re.test(lines[i])) { add({ file: f.path, line: i + 1, rule: p.id, message: 'matches configured sensitive pattern (text not shown)' }); n++ }
    }
  }
  const scope = `built-in rules + ${patterns.length} custom pattern(s) + ${(s.paths || []).length} custom path rule(s); binary files not inspected`
  const w = waived.length ? ` ${waived.length} finding(s) waived by policy.` : ''
  return findings.length
    ? { status: 'FAIL', summary: `${findings.length} sensitive-content flag(s) (${scope}).${w}`, findings: cap(findings), waived }
    : { status: 'PASS', summary: `no flags (${scope}).${w}`, findings: [], waived }
}

function stripCode(md) {
  return md.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, '').replace(/`[^`\n]*`/g, '')
}
function linkTargets(md) {
  const t = []
  const text = stripCode(md)
  for (const m of text.matchAll(/!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+["'(][^)]*)?\)/g)) t.push(m[1])
  for (const m of text.matchAll(/^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)/gm)) t.push(m[1])
  for (const m of text.matchAll(/<(?:img|a|source)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) t.push(m[1])
  return t
}

function links(ctx) {
  const md = ctx.files.filter((f) => /\.(md|markdown)$/i.test(f.path))
  if (!md.length) return { status: 'PASS', summary: 'no Markdown files in the candidate.', findings: [] }
  const exact = new Set(ctx.files.map((f) => f.path))
  const lower = new Map(ctx.files.map((f) => [f.path.toLowerCase(), f.path]))
  const excluded = new Set(ctx.excluded.map((e) => e.path))
  const findings = []
  let count = 0
  for (const f of md) {
    for (const raw of linkTargets(ctx.readCandidate(f.path).toString('utf8'))) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith('#') || raw.startsWith('//')) continue
      count++
      let target = raw.split('#')[0].split('?')[0]
      try { target = decodeURIComponent(target) } catch {}
      if (!target) continue
      const resolved = path.posix.normalize(target.startsWith('/') ? target.slice(1) : path.posix.join(path.posix.dirname(f.path), target)).replace(/\/$/, '')
      const bad = (message) => findings.push({ file: f.path, target: raw, message })
      if (resolved.startsWith('..') || resolved === '.') bad('points outside the deliverable')
      else if (exact.has(resolved) || ctx.files.some((x) => x.path.startsWith(resolved + '/'))) continue
      else if (lower.has(resolved.toLowerCase())) bad(`case mismatch with ${lower.get(resolved.toLowerCase())} (breaks on case-sensitive hosts)`)
      else if (excluded.has(resolved)) bad('target exists in the source but is excluded from the deliverable')
      else bad('target is not in the deliverable')
    }
  }
  return findings.length
    ? { status: 'FAIL', summary: `${findings.length} of ${count} relative link(s)/image(s) broken in the deliverable layout.`, findings: cap(findings) }
    : { status: 'PASS', summary: `${count} relative link(s)/image(s) in ${md.length} Markdown file(s) resolve inside the deliverable.`, findings: [] }
}

function provenance(ctx) {
  const rules = ctx.policy.provenance || []
  if (!rules.length) return { status: 'INCOMPLETE', summary: 'no provenance rules configured, so generated-document freshness was not assessed. Remove "provenance" from requiredChecks if this deliverable has no generated documents.', findings: [] }
  const byPath = new Map(ctx.files.map((f) => [f.path, f]))
  const findings = []
  for (const r of rules) {
    const out = byPath.get(r.output)
    if (!out) { findings.push({ status: 'FAIL', file: r.output, message: 'generated document is missing from the candidate' }); continue }
    const raw = ctx.read(r.record)
    let rec
    try { rec = raw && JSON.parse(raw.toString('utf8')) } catch {}
    if (!rec) { findings.push({ status: 'INCOMPLETE', file: r.output, message: `no readable build record at ${r.record}; freshness unknown (timestamps are not evidence)` }); continue }
    if (rec.output?.sha256 !== out.sha256) { findings.push({ status: 'FAIL', file: r.output, message: 'build record describes a different output (edited or regenerated without updating the record)' }); continue }
    for (const inp of r.inputs) {
      const cur = ctx.read(inp)
      const recorded = rec.inputs?.[inp]
      if (!cur) findings.push({ status: 'FAIL', file: r.output, message: `input ${inp} no longer exists in the source` })
      else if (!recorded) findings.push({ status: 'INCOMPLETE', file: r.output, message: `build record does not cover input ${inp}` })
      else if (recorded !== sha256(cur)) findings.push({ status: 'FAIL', file: r.output, message: `stale: input ${inp} changed since the document was generated` })
    }
  }
  const status = findings.some((f) => f.status === 'FAIL') ? 'FAIL' : findings.length ? 'INCOMPLETE' : 'PASS'
  return { status, summary: status === 'PASS' ? `${rules.length} generated document(s) match their build records and current inputs.` : `${findings.length} provenance problem(s) across ${rules.length} rule(s).`, findings }
}

function binaries(ctx) {
  const bins = ctx.files.filter((f) => isBinary(ctx.readCandidate(f.path)))
  return bins.length
    ? { status: 'INCOMPLETE', summary: `${bins.length} binary file(s) were not inspected by text-based checks (secrets, sensitive patterns, links). Uninspected is not safe: review them yourself.`, findings: cap(bins.map((f) => ({ file: f.path, message: `uninspected binary (${f.size} bytes)` }))) }
    : { status: 'PASS', summary: 'no binary files; every file was text-inspected.', findings: [] }
}

const LFS = /^version https:\/\/git-lfs\.github\.com\/spec\/v1\r?\noid sha256:([0-9a-f]{64})\r?\nsize (\d+)\r?\n?/
function lfs(ctx) {
  const findings = []
  const common = git(ctx.source.repo, ['rev-parse', '--git-common-dir'], { allowFail: true }).stdout.toString().trim()
  const gitDir = common ? path.resolve(ctx.source.repo, common) : null
  for (const f of ctx.files) {
    if (f.size > 1024) {
      if (path.posix.basename(f.path) !== '.gitattributes') continue
    }
    const text = ctx.readCandidate(f.path).toString('utf8')
    if (path.posix.basename(f.path) === '.gitattributes' && /filter=lfs/.test(text)) {
      findings.push({ file: f.path, message: 'declares Git LFS filters; the snapshot publisher pushes plain files and uploads no LFS objects' })
      continue
    }
    const m = LFS.exec(text)
    if (!m) continue
    const local = gitDir && fs.existsSync(path.join(gitDir, 'lfs', 'objects', m[1].slice(0, 2), m[1].slice(2, 4), m[1]))
    findings.push({ file: f.path, message: `unresolved LFS pointer (${m[2]} byte asset). Recipients would get a ${f.size}-byte pointer, not the asset. ${local ? 'The object exists in the local LFS store; materialise it into the source (e.g. via a worktree path) to publish the real file.' : 'The object is NOT in the local LFS store, so the asset is unavailable here.'}` })
  }
  return findings.length
    ? { status: 'FAIL', summary: `${findings.length} Git LFS problem(s).`, findings }
    : { status: 'PASS', summary: 'no LFS pointers or LFS filter declarations in the candidate.', findings: [] }
}

function history(ctx) {
  return ctx.policy.mode === 'history'
    ? { status: 'FAIL', summary: 'history publication is not supported: every outgoing commit and the blobs it references would need inspection, and a clean tree proves nothing about reachable history. Refused; use mode "snapshot".', findings: [] }
    : { status: 'PASS', summary: 'snapshot mode: the candidate is published as one new commit on the destination branch. No source commits, history, tags or refs are pushed.', findings: [] }
}

module.exports = { paths, secrets, sensitive, links, provenance, binaries, lfs, history, isBinary, linkTargets }
