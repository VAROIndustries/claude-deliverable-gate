'use strict'
// GitHub destination verification and snapshot publication.
// Publication builds the commit with plumbing (hash-object/mktree/commit-tree) straight from the approved
// snapshot, so line-ending conversion, LFS filters, .gitattributes and commit hooks cannot alter what is pushed.
const fs = require('node:fs')
const path = require('node:path')
const { run, git, gitBlobId, rmTree } = require('./util')

// Push and ls-remote authenticate as gh's active account, the same account the check verifies.
const GIT_CFG = ['-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential', '-c', 'core.autocrlf=false']

const remoteUrl = (d) => `https://github.com/${d.owner}/${d.repo}.git`
const identity = (d) => `github:${d.owner}/${d.repo}@${d.branch} (${d.visibility}, as ${d.account})`
const ghDefault = (args) => run('gh', args)

function checkDestination(policy, opts = {}) {
  const d = policy.destination
  const gh = opts.gh || ghDefault
  const url = opts.remoteUrl || remoteUrl(d)
  const base = { identity: identity(d), head: undefined }
  const findings = []
  const parse = (r) => { try { return JSON.parse(r.stdout.toString()) } catch { return null } }

  const user = gh(['api', 'user'])
  const login = user.status === 0 && parse(user)?.login
  if (!login) return { ...base, status: 'INCOMPLETE', summary: 'could not determine the active gh account (is gh installed and logged in?).', findings }
  if (login.toLowerCase() !== d.account.toLowerCase()) findings.push({ message: `active gh account is ${login}; policy expects ${d.account}. The account is never switched automatically.` })

  const repoRes = gh(['api', `repos/${d.owner}/${d.repo}`])
  const repo = repoRes.status === 0 && parse(repoRes)
  if (!repo) {
    findings.push({ message: `repository ${d.owner}/${d.repo} not found or not visible to ${login}. This plugin never creates repositories.` })
  } else {
    if (repo.full_name?.toLowerCase() !== `${d.owner}/${d.repo}`.toLowerCase()) findings.push({ message: `GitHub resolves this repository to ${repo.full_name} (renamed or transferred).` })
    if (repo.owner?.login?.toLowerCase() !== d.owner.toLowerCase()) findings.push({ message: `owner is ${repo.owner?.login}, policy expects ${d.owner}.` })
    if (repo.visibility !== d.visibility) findings.push({ message: `visibility is ${repo.visibility}, policy expects ${d.visibility}. Visibility is never changed automatically.` })
    if (!repo.permissions?.push) findings.push({ message: `${login} has no push permission on ${repo.full_name}.` })
    if (repo.archived) findings.push({ message: 'repository is archived.' })
  }

  const ls = git(process.cwd(), [...GIT_CFG, 'ls-remote', url, `refs/heads/${d.branch}`], { allowFail: true })
  if (ls.status !== 0) {
    if (!findings.length) return { ...base, status: 'INCOMPLETE', summary: `could not read branch ${d.branch} at the destination.`, findings }
  } else base.head = ls.stdout.toString().split(/\s/)[0] || null

  const author = d.commitIdentity ? `${d.commitIdentity.name} <${d.commitIdentity.email}>` : 'inherited from git config (set destination.commitIdentity to pin it)'
  return findings.length
    ? { ...base, status: 'FAIL', summary: `destination does not match policy (${findings.length} problem(s)).`, findings }
    : { ...base, status: 'PASS', summary: `${repo.full_name} is ${repo.visibility}, pushable by ${login}; branch ${d.branch} ${base.head ? 'at ' + base.head.slice(0, 12) : 'does not exist yet (first publish creates it)'}. Commit author: ${author}.`, findings }
}

// Optional Identity Guard integration via its documented CLI (exit 0 PASS, 1 MISMATCH, 2 UNKNOWN, 3 error).
function findIdentityGuard() {
  if (process.env.IDENTITY_GUARD_BIN) return process.env.IDENTITY_GUARD_BIN
  const cache = path.join(require('node:os').homedir(), '.claude', 'plugins', 'cache')
  const hits = []
  try {
    for (const mk of fs.readdirSync(cache)) {
      const dir = path.join(cache, mk, 'identity-guard')
      if (!fs.existsSync(dir)) continue
      for (const v of fs.readdirSync(dir)) {
        const bin = path.join(dir, v, 'bin', 'idguard.mjs')
        if (fs.existsSync(bin)) hits.push(bin)
      }
    }
  } catch {}
  return hits.sort().pop() || null
}
function identityGuard(policy, url) {
  const bin = findIdentityGuard()
  if (!bin) return { status: 'NOT-INSTALLED', summary: 'Identity Guard not installed (optional).' }
  const r = run(process.execPath, [bin, 'check', '--', 'git', 'push', url, policy.destination.branch], { cwd: policy.source.repo })
  const status = { 0: 'PASS', 1: 'FAIL', 2: 'UNKNOWN' }[r.status] || 'ERROR'
  return { status, summary: `Identity Guard: ${status}` }
}

function publishSnapshot({ policy, candDir, manifest, approval, workDir, opts = {} }) {
  const d = policy.destination
  const url = opts.remoteUrl || remoteUrl(d)
  rmTree(workDir)
  fs.mkdirSync(workDir, { recursive: true })
  const g = (args, o) => git(workDir, [...GIT_CFG, ...args], o)
  const out = (args, o) => g(args, o).stdout.toString().trim()
  g(['init', '-q', '--bare'])

  let parent = null
  if (approval.destinationHead) {
    g(['fetch', '-q', '--depth', '1', '--no-tags', url, `refs/heads/${d.branch}`])
    parent = out(['rev-parse', 'FETCH_HEAD'])
    if (parent !== approval.destinationHead) throw new Error(`destination branch moved since approval (${approval.destinationHead.slice(0, 12)} -> ${parent.slice(0, 12)}); re-run check and approve`)
  }

  // Blobs straight from the snapshot bytes, cross-checked against the manifest.
  const filesDir = path.join(candDir, 'files')
  const abs = manifest.files.map((f) => path.join(filesDir, ...f.path.split('/')))
  const oids = out(['hash-object', '-w', '--no-filters', '--stdin-paths'], { input: abs.join('\n') + '\n' }).split(/\r?\n/)
  manifest.files.forEach((f, i) => {
    if (oids[i] !== gitBlobId(fs.readFileSync(abs[i]))) throw new Error(`blob mismatch for ${f.path}; aborting`)
  })

  const root = { dirs: new Map(), files: [] }
  manifest.files.forEach((f, i) => {
    const segs = f.path.split('/')
    let node = root
    for (const s of segs.slice(0, -1)) {
      if (!node.dirs.has(s)) node.dirs.set(s, { dirs: new Map(), files: [] })
      node = node.dirs.get(s)
    }
    node.files.push(`${f.mode} blob ${oids[i]}\t${segs.at(-1)}`)
  })
  const emit = (node) => {
    const lines = [...[...node.dirs].map(([n, c]) => `040000 tree ${emit(c)}\t${n}`), ...node.files]
    return out(['mktree', '-z'], { input: lines.join('\0') + '\0' })
  }
  const tree = emit(root)

  // Verify the tree is exactly the manifest before anything leaves the machine.
  const listed = out(['ls-tree', '-r', '-z', tree]).split('\0').filter(Boolean)
  const want = new Map(manifest.files.map((f, i) => [f.path, `${f.mode} blob ${oids[i]}`]))
  if (listed.length !== want.size || listed.some((l) => want.get(l.slice(l.indexOf('\t') + 1)) !== l.slice(0, l.indexOf('\t')))) throw new Error('built tree does not match the manifest; aborting')

  if (parent && out(['rev-parse', `${parent}^{tree}`]) === tree) return { pushed: false, commit: parent, tree, message: 'destination already matches the approved candidate; nothing pushed' }

  const env = { ...process.env }
  if (d.commitIdentity) {
    env.GIT_AUTHOR_NAME = env.GIT_COMMITTER_NAME = d.commitIdentity.name
    env.GIT_AUTHOR_EMAIL = env.GIT_COMMITTER_EMAIL = d.commitIdentity.email
  }
  const msg = `Publish deliverable ${policy.name} (candidate ${manifest.candidateId})\n\nDeliverable-Gate-Candidate: sha256:${manifest.candidateHash}\nDeliverable-Gate-Approval: sha256:${approval.approvalHash}\n`
  const commit = out(['commit-tree', tree, ...(parent ? ['-p', parent] : []), '-F', '-'], { input: msg, env })

  // Plain push of a single new commit: no force, no tags, no other refs. A non-fast-forward is rejected by the server.
  g(['push', '--no-follow-tags', url, `${commit}:refs/heads/${d.branch}`])
  const after = out(['ls-remote', url, `refs/heads/${d.branch}`]).split(/\s/)[0]
  if (after !== commit) throw new Error(`push reported success but destination head is ${after}, expected ${commit}`)
  const author = out(['log', '-1', '--format=%an <%ae>', commit])
  return { pushed: true, commit, tree, parent, author }
}

module.exports = { checkDestination, publishSnapshot, identity, remoteUrl, identityGuard, GIT_CFG }
