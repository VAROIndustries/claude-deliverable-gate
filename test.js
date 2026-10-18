'use strict'
// Focused tests. Every fixture is synthetic and generated at runtime in a temp dir; secrets are assembled at
// runtime so this repository never contains one. "Publishing" only ever targets a local bare repository.
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { pathToFileURL } = require('node:url')
const { spawnSync } = require('node:child_process')

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dgate-test-'))
process.env.DELIVERABLE_GATE_HOME = path.join(TMP, 'home')
const gate = require('./lib/gate')
const { validatePolicy, pathProblem, symlinkVerdict } = require('./lib/snapshot')
const { decide } = require('./hook')
const { writeJson, rmTree } = require('./lib/util')

const ALL = ['paths', 'secrets', 'sensitive', 'links', 'provenance', 'binaries', 'lfs', 'destination', 'history']
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex')
let n = 0

function sh(cwd, args, input) {
  const r = spawnSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], { cwd, input, encoding: 'utf8' })
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`)
  return r.stdout.trim()
}
function writeFiles(dir, files) {
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true })
    fs.writeFileSync(path.join(dir, rel), body)
  }
}
function makeRepo(files) {
  const dir = path.join(TMP, `src-${++n}`)
  fs.mkdirSync(dir)
  sh(dir, ['init', '-q', '-b', 'main'])
  writeFiles(dir, files)
  sh(dir, ['add', '-A'])
  sh(dir, ['commit', '-q', '-m', 'fixture'])
  return dir
}
// Add a raw index entry (symlinks, case collisions) without needing OS support for it.
function addEntry(dir, mode, rel, content) {
  const oid = sh(dir, ['hash-object', '-w', '--stdin'], content)
  sh(dir, ['update-index', '--add', '--cacheinfo', `${mode},${oid},${rel}`])
}
function bare() {
  const dir = path.join(TMP, `remote-${++n}.git`)
  sh(TMP, ['init', '-q', '--bare', '-b', 'main', dir])
  return { dir, url: pathToFileURL(dir).href }
}
function fakeGh({ login = 'tester', owner = 'acme', repo = 'handover', visibility = 'private', push = true } = {}) {
  return (args) => {
    const out = args[1] === 'user' ? { login } : { full_name: `${owner}/${repo}`, owner: { login: owner }, visibility, permissions: { push }, archived: false }
    return { status: 0, stdout: Buffer.from(JSON.stringify(out)), stderr: '' }
  }
}
function policy(name, repo, extra = {}) {
  const p = {
    name,
    audience: 'test',
    mode: 'snapshot',
    source: { repo },
    include: ['**'],
    exclude: [{ glob: '**/correspondence/**', reason: 'client correspondence' }],
    destination: { type: 'github', owner: 'acme', repo: 'handover', branch: 'main', visibility: 'private', account: 'tester', commitIdentity: { name: 'Gate Test', email: 'gate@example.invalid' } },
    requiredChecks: ALL.filter((c) => c !== 'provenance'),
    ...extra,
  }
  writeJson(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables', name, 'policy.json'), p)
  return p
}
const NO_SCANNER = { gitleaks: path.join(TMP, 'no-such-gitleaks') }
const findings = (r, c) => r.report.checks[c].findings

// Locate a real gitleaks for the secrets test; the test reports skip (never pass) without one.
function findGitleaks() {
  const cands = [process.env.DELIVERABLE_GATE_GITLEAKS, 'gitleaks', path.join(process.env.LOCALAPPDATA || '', 'Microsoft/WinGet/Packages/Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe/gitleaks.exe')]
  return cands.find((c) => c && spawnSync(c, ['version']).status === 0)
}
const fakeToken = () => 'ghp_' + crypto.randomBytes(27).toString('base64').replace(/[^A-Za-z0-9]/g, 'x').slice(0, 36)

test('policy rejects allowlist escapes and path validator catches unsafe names', () => {
  const base = { name: 'x', source: { repo: '.' }, destination: { type: 'github', owner: 'a', repo: 'b', branch: 'main', visibility: 'private', account: 'c' } }
  for (const g of ['../outside/**', '/etc/**', 'C:/x/**', 'docs\\..\\x']) assert.throws(() => validatePolicy({ ...base, include: [g] }), /escapes|relative/)
  assert.throws(() => validatePolicy({ ...base, include: ['**'], exclude: [{ glob: '**/*.eml' }] }), /reason/)
  assert.throws(() => validatePolicy({ ...base, include: ['**'], destination: { ...base.destination, type: 'ftp' } }), /github/)
  assert.ok(validatePolicy({ ...base, include: ['**'] }))
  for (const p of ['a/../b', './a', 'a/.git/config', 'con.txt', 'trailing. /x', 'a\\b']) assert.ok(pathProblem(p), p)
  assert.equal(pathProblem('docs/ok.md'), null)
  assert.match(symlinkVerdict('docs/l', '../../x'), /escapes/)
  assert.match(symlinkVerdict('docs/l', '/etc/passwd'), /escapes/)
  assert.match(symlinkVerdict('docs/l', '../a.md'), /inside root/)
})

test('snapshot honours allowlist and exclusions, ignores unrelated working-tree changes, never touches the source', () => {
  const repo = makeRepo({ 'README.md': '# Hi\n', 'docs/guide.md': 'v1\n', 'notes/todo.md': 'x\n', 'correspondence/2026-03-client.eml': 'From: a@b.example\nSubject: hi\n\nbody\n' })
  fs.writeFileSync(path.join(repo, 'docs/guide.md'), 'UNCOMMITTED EDIT\n')
  fs.writeFileSync(path.join(repo, 'docs/untracked.md'), 'untracked\n')
  policy('allow', repo, { include: ['README.md', 'docs/**', 'correspondence/**'] })
  const before = sh(repo, ['status', '--porcelain'])
  const listing = fs.readdirSync(repo, { recursive: true }).sort().join('|')
  const r = gate.check('allow', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  const m = JSON.parse(fs.readFileSync(path.join(r.dir, 'manifest.json'), 'utf8'))
  assert.deepEqual(m.files.map((f) => f.path), ['README.md', 'docs/guide.md'])
  assert.equal(fs.readFileSync(path.join(r.dir, 'files/docs/guide.md'), 'utf8'), 'v1\n', 'committed content, not the uncommitted edit')
  assert.equal(m.files[1].worktreeDiffers, true)
  assert.equal(m.source.dirty, true)
  assert.deepEqual(m.excluded, [{ path: 'correspondence/2026-03-client.eml', reason: 'client correspondence', rule: '**/correspondence/**' }, { path: 'notes/todo.md', reason: 'not in allowlist' }])
  assert.equal(m.files[0].sha256, sha('# Hi\n'))
  assert.equal(sh(repo, ['status', '--porcelain']), before)
  assert.equal(fs.readdirSync(repo, { recursive: true }).sort().join('|'), listing, 'no files created in the source')
  assert.match(r.md, /2 file\(s\)/)
  assert.match(r.md, /NOT in the candidate/)
})

test('symlink escapes, internal symlinks, case collisions and unexpected types FAIL', (t) => {
  const repo = makeRepo({ 'a.md': 'a\n' })
  addEntry(repo, '120000', 'docs/escape', '../../outside/secret.txt')
  addEntry(repo, '120000', 'docs/inside', '../a.md')
  addEntry(repo, '100644', 'Docs/Readme.md', 'one\n')
  addEntry(repo, '100644', 'docs/readme.md', 'two\n')
  addEntry(repo, '100644', 'tools/bundle.zip', 'PK')
  sh(repo, ['commit', '-q', '-m', 'odd entries'])
  policy('links-and-types', repo)
  const r = gate.check('links-and-types', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  const msgs = findings(r, 'paths').map((f) => `${f.file}: ${f.message}`).join('\n')
  assert.equal(r.report.checks.paths.status, 'FAIL')
  assert.match(msgs, /docs\/escape: symlink escapes/)
  assert.match(msgs, /docs\/inside: symlink inside root/)
  assert.match(msgs, /case collision/)
  assert.match(msgs, /bundle\.zip: unexpected file type/)
  assert.equal(r.verdict, 'BLOCKED')
  assert.ok(!fs.existsSync(path.join(r.dir, 'files/docs/escape')))

  // Working-tree junction/symlink pointing outside the root (worktree paths are opted in explicitly).
  const outside = fs.mkdtempSync(path.join(TMP, 'outside-'))
  fs.mkdirSync(path.join(repo, 'export'))
  try { fs.symlinkSync(outside, path.join(repo, 'export', 'linked'), 'junction') } catch (e) { return t.skip(`cannot create junction/symlink here: ${e.code}`) }
  policy('wt-link', repo, { source: { repo, worktreePaths: ['export/**'] } })
  const r2 = gate.check('wt-link', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  assert.match(findings(r2, 'paths').map((f) => f.message).join('\n'), /escapes the source root/)
})

test('sensitive content is flagged without being displayed', () => {
  const repo = makeRepo({
    'notes/forwarded.txt': 'From: someone@client.example\nTo: me@example.invalid\nSubject: pricing\n\nCONFIDENTIAL-BODY-MARKER\n',
    'docs/plan.md': 'intro\nThe Orchid launch plan PROJECT-ORCHID details\n',
    'logs/session_log.md': 'log\n',
    'config/.env.example': 'KEY=\n',
    'config/app.local.json': '{}\n',
  })
  policy('sens', repo, { sensitive: { patterns: [{ id: 'client-codename', regex: 'PROJECT-ORCHID' }], allow: [{ rule: 'local-settings', glob: 'config/app.local.json', reason: 'reviewed default' }] } })
  const r = gate.check('sens', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  const f = findings(r, 'sensitive')
  assert.equal(r.report.checks.sensitive.status, 'FAIL')
  assert.ok(f.some((x) => x.file === 'notes/forwarded.txt' && x.rule === 'correspondence' && x.line === 1))
  assert.ok(f.some((x) => x.file === 'docs/plan.md' && x.rule === 'client-codename' && x.line === 2))
  assert.ok(f.some((x) => x.file === 'logs/session_log.md' && x.rule === 'session-log'))
  assert.ok(!f.some((x) => x.file === 'config/.env.example'), '.env.example templates are not local settings')
  assert.ok(!f.some((x) => x.file === 'config/app.local.json'), 'waived')
  assert.equal(r.report.checks.sensitive.waived.length, 1)
  const out = r.md + fs.readFileSync(path.join(r.dir, 'report.json'), 'utf8')
  for (const secret of ['CONFIDENTIAL-BODY-MARKER', 'Orchid launch plan', 'someone@client.example']) assert.ok(!out.includes(secret), `report leaks ${secret}`)
})

test('relative Markdown links and images are validated against the deliverable layout', () => {
  const repo = makeRepo({
    'README.md': [
      '[ok](docs/guide.md) [ok-anchor](docs/guide.md#setup) [dir](docs/)',
      '[broken](docs/missing.md)',
      '![logo](img/Logo.PNG)',
      '[outside](../../elsewhere.md)',
      '[excluded](correspondence/note.md)',
      '[web](https://example.com) [mail](mailto:a@example.com) [self](#top)',
      '<img src="img/logo.png">',
      '```', '[in code](nope.md)', '```',
      '[ref]: docs/gone.md',
    ].join('\n'),
    'docs/guide.md': '[back](../README.md)\n',
    'img/logo.png': 'not really a png',
    'correspondence/note.md': 'x',
  })
  policy('links', repo)
  const r = gate.check('links', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  const got = findings(r, 'links').map((f) => `${f.target} ${f.message}`)
  assert.equal(r.report.checks.links.status, 'FAIL')
  assert.equal(got.length, 5, got.join('\n'))
  assert.ok(got.some((g) => /missing\.md target is not in/.test(g)))
  assert.ok(got.some((g) => /Logo\.PNG case mismatch/.test(g)))
  assert.ok(got.some((g) => /elsewhere\.md points outside/.test(g)))
  assert.ok(got.some((g) => /note\.md .*excluded/.test(g)))
  assert.ok(got.some((g) => /gone\.md/.test(g)))
})

test('generated documents: stale, missing record, missing output and fresh', () => {
  const pdf = Buffer.from('%PDF-1.7\n\0binary')
  const rec = (inputHash) => JSON.stringify({ output: { path: 'docs/guide.pdf', sha256: sha(pdf) }, inputs: { 'docs/guide.md': inputHash } })
  const repo = makeRepo({ 'docs/guide.md': 'v2 source\n', 'docs/guide.pdf': pdf, 'docs/guide.pdf.provenance.json': rec(sha('v1 source\n')) })
  const rule = { output: 'docs/guide.pdf', inputs: ['docs/guide.md'], record: 'docs/guide.pdf.provenance.json' }
  const run = (name, extra) => { policy(name, repo, { requiredChecks: ALL, ...extra }); return gate.check(name, { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER }).report.checks.provenance }

  let c = run('prov-stale', { provenance: [rule] })
  assert.equal(c.status, 'FAIL')
  assert.match(c.findings[0].message, /stale: input docs\/guide\.md changed/)

  c = run('prov-norecord', { provenance: [{ ...rule, record: 'docs/none.json' }] })
  assert.equal(c.status, 'INCOMPLETE')
  assert.match(c.findings[0].message, /timestamps are not evidence/)

  c = run('prov-missing', { provenance: [rule], exclude: [{ glob: '**/*.pdf', reason: 'test' }] })
  assert.equal(c.status, 'FAIL')
  assert.match(c.findings[0].message, /missing from the candidate/)

  c = run('prov-none', {})
  assert.equal(c.status, 'INCOMPLETE', 'no rules is not a PASS')

  fs.writeFileSync(path.join(repo, 'docs/guide.pdf.provenance.json'), rec(sha('v2 source\n')))
  sh(repo, ['commit', '-qam', 'rebuild record'])
  c = run('prov-fresh', { provenance: [rule] })
  assert.equal(c.status, 'PASS', JSON.stringify(c))
})

test('binaries are reported uninspected and LFS pointers fail with availability', () => {
  const oid = 'a'.repeat(64)
  const repo = makeRepo({
    'assets/blob.bin': Buffer.from([1, 2, 0, 3]),
    'assets/video.mp4': `version https://git-lfs.github.com/spec/v1\noid sha256:${oid}\nsize 1048576\n`,
  })
  policy('bin-lfs', repo)
  const r = gate.check('bin-lfs', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  assert.equal(r.report.checks.binaries.status, 'INCOMPLETE')
  assert.deepEqual(findings(r, 'binaries').map((f) => f.file), ['assets/blob.bin'])
  assert.equal(r.report.checks.lfs.status, 'FAIL')
  assert.match(findings(r, 'lfs')[0].message, /NOT in the local LFS store/)
})

test('missing secret scanner is INCOMPLETE, never PASS', () => {
  const repo = makeRepo({ 'a.md': 'a\n' })
  policy('noscan', repo)
  const r = gate.check('noscan', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  assert.equal(r.report.checks.secrets.status, 'INCOMPLETE')
  assert.equal(r.verdict, 'INCOMPLETE')
})

test('gitleaks finds a synthetic secret despite candidate-supplied ignores, without printing it', (t) => {
  const bin = findGitleaks()
  if (!bin) return t.skip('gitleaks not installed')
  const token = fakeToken()
  const repo = makeRepo({
    'src/config.js': `const token = "${token}" // gitleaks:allow\n`,
    '.gitleaks.toml': '[allowlist]\npaths = [".*"]\n',
    '.gitleaksignore': '*\n',
  })
  policy('secret', repo)
  const r = gate.check('secret', { gh: fakeGh(), remoteUrl: bare().url, gitleaks: bin })
  assert.equal(r.report.checks.secrets.status, 'FAIL', r.report.checks.secrets.summary)
  assert.ok(findings(r, 'secrets').some((f) => f.file === 'src/config.js' && f.line === 1))
  const all = r.md + fs.readFileSync(path.join(r.dir, 'report.json'), 'utf8') + fs.readdirSync(path.join(r.dir, 'scan')).map((f) => fs.readFileSync(path.join(r.dir, 'scan', f), 'utf8')).join('')
  assert.ok(!all.includes(token))
})

test('history mode is refused; destination mismatches FAIL', () => {
  const repo = makeRepo({ 'a.md': 'a\n' })
  policy('hist', repo, { mode: 'history' })
  const r = gate.check('hist', { gh: fakeGh(), remoteUrl: bare().url, ...NO_SCANNER })
  assert.equal(r.report.checks.history.status, 'FAIL')
  assert.equal(r.verdict, 'BLOCKED')

  policy('dest', repo)
  const d = gate.check('dest', { gh: fakeGh({ visibility: 'public', login: 'someone-else', owner: 'evil' }), remoteUrl: bare().url, ...NO_SCANNER }).report.checks.destination
  assert.equal(d.status, 'FAIL')
  const msgs = d.findings.map((f) => f.message).join('\n')
  assert.match(msgs, /visibility is public/)
  assert.match(msgs, /active gh account is someone-else/)
  assert.match(msgs, /owner is evil/)
})

test('end to end: approve and publish a snapshot, history stays home, and approvals invalidate', () => {
  const token = fakeToken()
  const repo = makeRepo({ 'README.md': '# Deliverable\n', 'src/app.js': `const k = "${token}"\n` })
  fs.writeFileSync(path.join(repo, 'src/app.js'), 'const k = process.env.K\n')
  sh(repo, ['commit', '-qam', 'remove secret (still in history)'])
  const remote = bare()
  const opts = { gh: fakeGh(), remoteUrl: remote.url, identityGuard: false, ...NO_SCANNER }
  policy('e2e', repo)

  const c1 = gate.check('e2e', opts)
  assert.equal(c1.verdict, 'INCOMPLETE')
  const dest = c1.report.destination
  assert.throws(() => gate.approve('e2e', c1.id, { destination: dest }), /INCOMPLETE: secrets/)
  assert.throws(() => gate.approve('e2e', c1.id, { destination: dest.replace('main', 'prod'), acceptIncomplete: ['secrets'] }), /restate the exact destination/)
  assert.throws(() => gate.publish('e2e', c1.id, opts), /not approved/)
  gate.approve('e2e', c1.id, { destination: dest, acceptIncomplete: ['secrets'] })

  const p1 = gate.publish('e2e', c1.id, opts)
  assert.equal(p1.pushed, true)
  assert.equal(p1.author, 'Gate Test <gate@example.invalid>')
  const tree = sh(remote.dir, ['ls-tree', '-r', '--name-only', 'main']).split('\n')
  assert.deepEqual(tree, ['README.md', 'src/app.js'])
  assert.equal(sh(remote.dir, ['rev-list', '--count', 'main']), '1', 'one snapshot commit, no source history')
  const objects = sh(remote.dir, ['cat-file', '--batch-all-objects', '--batch'])
  assert.ok(!objects.includes(token), 'secret from source history must not reach the destination')

  // Re-publishing the same approved candidate is a no-op.
  // (A new check is needed because the destination head moved; the old approval is now stale.)
  assert.throws(() => gate.publish('e2e', c1.id, opts), /destination branch moved/)

  // Second candidate with a change: diff against the last approved manifest, publish on top.
  fs.writeFileSync(path.join(repo, 'README.md'), '# Deliverable v2\n')
  sh(repo, ['commit', '-qam', 'v2'])
  const c2 = gate.check('e2e', opts)
  assert.deepEqual(c2.report.changes.modified, ['README.md'])
  gate.approve('e2e', c2.id, { destination: dest, acceptIncomplete: ['secrets'] })

  // Mutation after approval invalidates it.
  const f = path.join(c2.dir, 'files', 'README.md')
  fs.chmodSync(f, 0o644)
  fs.writeFileSync(f, '# tampered\n')
  assert.throws(() => gate.publish('e2e', c2.id, opts), /modified since check: README\.md/)
  fs.writeFileSync(f, '# Deliverable v2\n')
  fs.writeFileSync(path.join(c2.dir, 'files', 'extra.txt'), 'sneaky')
  assert.throws(() => gate.publish('e2e', c2.id, opts), /unexpected file in snapshot: extra\.txt/)
  fs.rmSync(path.join(c2.dir, 'files', 'extra.txt'))

  // Destination change in policy invalidates it.
  const p = JSON.parse(fs.readFileSync(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables/e2e/policy.json'), 'utf8'))
  writeJson(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables/e2e/policy.json'), { ...p, destination: { ...p.destination, branch: 'release' } })
  assert.throws(() => gate.publish('e2e', c2.id, opts), /policy changed|destination changed/)
  writeJson(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables/e2e/policy.json'), p)
  assert.match(gate.status('e2e').candidates.find((x) => x.id === c2.id).approval, /^approved/)

  // Any policy change (not just destination) invalidates it.
  writeJson(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables/e2e/policy.json'), { ...p, requiredChecks: ALL })
  assert.throws(() => gate.publish('e2e', c2.id, opts), /policy changed/)
  writeJson(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables/e2e/policy.json'), p)

  // Destination identity drift at publish time is refused even with a valid approval.
  assert.throws(() => gate.publish('e2e', c2.id, { ...opts, gh: fakeGh({ visibility: 'public' }) }), /no longer passes/)

  const p2 = gate.publish('e2e', c2.id, opts)
  assert.equal(p2.parent, p1.commit)
  assert.equal(sh(remote.dir, ['show', 'main:README.md']), '# Deliverable v2')

  // Retention.
  const cl = gate.clean('e2e', { keep: 0 })
  assert.ok(cl.kept.includes(c2.id), 'latest approved candidate is kept as the diff baseline')
  assert.ok(cl.removed.includes(c1.id))
})

test('a third party pushing after approval invalidates it', () => {
  const repo = makeRepo({ 'a.md': 'a\n' })
  const remote = bare()
  const opts = { gh: fakeGh(), remoteUrl: remote.url, identityGuard: false, ...NO_SCANNER }
  policy('race', repo, { requiredChecks: ['paths', 'destination', 'history'] })
  const c = gate.check('race', opts)
  gate.approve('race', c.id, { destination: c.report.destination })
  const other = makeRepo({ 'other.md': 'someone else\n' })
  sh(other, ['push', '-q', remote.url, 'main:main'])
  assert.throws(() => gate.publish('race', c.id, opts), /destination branch moved/)
  assert.equal(sh(remote.dir, ['ls-tree', '--name-only', 'main']), 'other.md')
})

test('advisory hook denies Claude pushes from registered sources only', () => {
  const repo = makeRepo({ 'a.md': 'a\n' })
  policy('hooked', repo)
  assert.match(decide({ tool_input: { command: 'git push origin main' }, cwd: repo }), /registered deliverable "hooked"/)
  assert.match(decide({ tool_input: { command: `git -C "${repo}" push` }, cwd: TMP }), /hooked/)
  assert.match(decide({ tool_input: { command: 'gh repo create acme/x --public --source=.' }, cwd: path.join(repo, 'sub') }), /hooked/)
  assert.equal(decide({ tool_input: { command: 'git status' }, cwd: repo }), null)
  assert.equal(decide({ tool_input: { command: 'git push' }, cwd: os.homedir() }), null)
})

test.after(() => rmTree(TMP))
