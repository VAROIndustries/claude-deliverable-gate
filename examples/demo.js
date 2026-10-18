'use strict'
// Regenerates examples/sample/{manifest.json,report.md} from a synthetic workspace.
// Offline: the destination is a local bare repo and gh is stubbed. Nothing is published.
//   node examples/demo.js
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { spawnSync } = require('node:child_process')
const { pathToFileURL } = require('node:url')

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dgate-demo-'))
process.env.DELIVERABLE_GATE_HOME = path.join(TMP, 'home')
const gate = require('../lib/gate')
const { writeJson, rmTree } = require('../lib/util')

const git = (cwd, ...a) => spawnSync('git', ['-c', 'user.name=Demo', '-c', 'user.email=demo@example.invalid', '-c', 'core.autocrlf=false', ...a], { cwd, encoding: 'utf8' })
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex')
const ws = path.join(TMP, 'example-portal')
const files = {
  'README.md': '# Example Portal handover\n\nSee the [setup guide](docs/setup.md) and the [API notes](docs/api.md).\n\n![Architecture](docs/img/architecture.png)\n',
  'docs/setup.md': '# Setup\n\nRun `npm start`. Back to [README](../README.md).\n',
  'docs/img/architecture.png': Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]),
  'docs/handover-guide.md': 'Handover guide, revision 2\n',
  'docs/handover-guide.pdf': Buffer.from('%PDF-1.7\n\0demo'),
  'src/index.js': 'module.exports = () => "hello"\n',
  'correspondence/2026-09-12-kickoff.eml': 'From: pm@client.example\nSubject: kickoff\n\n(synthetic)\n',
  'docs/internal/rates.md': 'internal (synthetic)\n',
  'notes/meeting.txt': 'scratch\n',
}
files['docs/handover-guide.pdf.provenance.json'] = JSON.stringify({ tool: 'pandoc 3.1', output: { path: 'docs/handover-guide.pdf', sha256: sha(files['docs/handover-guide.pdf']) }, inputs: { 'docs/handover-guide.md': sha('Handover guide, revision 1\n') } }, null, 2)
for (const [rel, body] of Object.entries(files)) {
  fs.mkdirSync(path.dirname(path.join(ws, rel)), { recursive: true })
  fs.writeFileSync(path.join(ws, rel), body)
}
git(ws, 'init', '-q', '-b', 'main')
git(ws, 'add', '-A')
git(ws, 'commit', '-q', '-m', 'demo')
fs.writeFileSync(path.join(ws, 'src/index.js'), 'module.exports = () => "work in progress"\n') // unrelated uncommitted change

const remote = path.join(TMP, 'remote.git')
git(TMP, 'init', '-q', '--bare', remote)
const policy = JSON.parse(fs.readFileSync(path.join(__dirname, 'policy.example.json'), 'utf8'))
policy.source.repo = ws
delete policy.sensitive.allow
writeJson(path.join(process.env.DELIVERABLE_GATE_HOME, 'deliverables', policy.name, 'policy.json'), policy)

const gh = (args) => ({ status: 0, stderr: '', stdout: Buffer.from(JSON.stringify(args[1] === 'user' ? { login: 'your-publishing-account' } : { full_name: 'example-client-org/portal-handover', owner: { login: 'example-client-org' }, visibility: 'private', permissions: { push: true } })) })
const leaks = [process.env.DELIVERABLE_GATE_GITLEAKS, 'gitleaks', path.join(process.env.LOCALAPPDATA || '', 'Microsoft/WinGet/Packages/Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe/gitleaks.exe')].find((c) => c && spawnSync(c, ['version']).status === 0)
const r = gate.check(policy.name, { gh, remoteUrl: pathToFileURL(remote).href, gitleaks: leaks })

// Scrub machine-specific paths before writing the committed sample.
const scrub = (s) => [ws, ws.split(path.sep).join('/'), JSON.stringify(ws).slice(1, -1)].reduce((acc, p) => acc.split(p).join('C:/Work/example-portal'), s)
const out = path.join(__dirname, 'sample')
fs.mkdirSync(out, { recursive: true })
fs.writeFileSync(path.join(out, 'manifest.json'), scrub(fs.readFileSync(path.join(r.dir, 'manifest.json'), 'utf8')))
fs.writeFileSync(path.join(out, 'report.md'), scrub(r.md))
console.log(`verdict ${r.verdict}; wrote examples/sample/manifest.json and report.md`)
rmTree(TMP)
