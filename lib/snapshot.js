'use strict'
// Policy validation and isolated candidate snapshots. Never writes to the source workspace.
const fs = require('node:fs')
const path = require('node:path')
const { sha256, matchAny, globPrefix, git, UsageError } = require('./util')

const CHECK_IDS = ['paths', 'secrets', 'sensitive', 'links', 'provenance', 'binaries', 'lfs', 'destination', 'history']
const MAX_FILE = 100 * 1024 * 1024 // GitHub rejects files over 100 MiB
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i

function badGlob(g) {
  return typeof g !== 'string' || !g || g.startsWith('/') || /^[a-z]:/i.test(g) || g.includes('\\') || g.split('/').includes('..')
}

function validatePolicy(p) {
  const errs = []
  const need = (cond, msg) => { if (!cond) errs.push(msg) }
  need(p && typeof p === 'object', 'policy must be a JSON object')
  if (errs.length) throw new UsageError(errs.join('; '))
  need(typeof p.name === 'string', 'name is required')
  need(['snapshot', 'history'].includes(p.mode || 'snapshot'), 'mode must be "snapshot" or "history"')
  need(p.source && typeof p.source.repo === 'string', 'source.repo is required')
  need(Array.isArray(p.include) && p.include.length > 0, 'include must list at least one glob (an explicit allowlist)')
  for (const g of p.include || []) need(!badGlob(g), `include glob escapes the source root or is not relative: ${JSON.stringify(g)}`)
  for (const e of p.exclude || []) need(e && !badGlob(e.glob) && typeof e.reason === 'string', `exclude entries need a relative "glob" and a "reason": ${JSON.stringify(e)}`)
  for (const g of p.source?.worktreePaths || []) need(!badGlob(g), `worktreePaths glob escapes the source root: ${JSON.stringify(g)}`)
  need(!p.source?.base || !badGlob(p.source.base), 'source.base must be a relative subdirectory')
  const d = p.destination || {}
  need(d.type === 'github', 'destination.type must be "github" (the only supported publisher)')
  for (const k of ['owner', 'repo', 'branch', 'visibility', 'account']) need(typeof d[k] === 'string' && d[k], `destination.${k} is required`)
  need(!d.owner || /^[A-Za-z0-9-]+$/.test(d.owner), 'destination.owner is not a valid GitHub owner')
  need(!d.repo || /^[A-Za-z0-9._-]+$/.test(d.repo), 'destination.repo is not a valid repository name')
  need(!d.branch || (/^[A-Za-z0-9._/-]+$/.test(d.branch) && !d.branch.includes('..')), 'destination.branch is not a valid branch name')
  need(['private', 'public', 'internal'].includes(d.visibility), 'destination.visibility must be private, public or internal')
  for (const c of p.requiredChecks || []) need(CHECK_IDS.includes(c), `unknown required check: ${c}`)
  for (const s of p.sensitive?.patterns || []) {
    try { new RegExp(s.regex, s.flags || 'i') } catch { errs.push(`sensitive pattern ${s.id} is not a valid regex`) }
  }
  for (const r of p.provenance || []) need(r.output && Array.isArray(r.inputs) && r.record, 'provenance rules need output, inputs[] and record')
  if (errs.length) throw new UsageError('policy invalid: ' + errs.join('; '))
  return { mode: 'snapshot', requiredChecks: CHECK_IDS, exclude: [], ...p }
}

// Problems with a relative candidate path itself (traversal, reserved names, things Git/Windows mangle).
function pathProblem(rel) {
  if (!rel || rel.startsWith('/') || /^[a-z]:/i.test(rel) || rel.includes('\\')) return 'not a relative POSIX path'
  if (/[\x00-\x1f]/.test(rel)) return 'contains control characters'
  const segs = rel.split('/')
  if (segs.includes('..') || segs.includes('.')) return 'path traversal segment'
  if (segs.some((s) => s.toLowerCase() === '.git')) return '.git path segment'
  if (segs.some((s) => RESERVED.test(s))) return 'Windows reserved device name'
  if (segs.some((s) => /[ .]$/.test(s))) return 'segment ends with a dot or space (renamed on Windows)'
  return null
}

function sourceReader(policy, rev) {
  const repo = policy.source.repo
  const base = (policy.source.base || '').replace(/\/+$/, '')
  const wt = policy.source.worktreePaths || []
  const full = (rel) => (base ? base + '/' + rel : rel)
  // Returns Buffer or null. Worktree paths read from disk, everything else from the pinned revision.
  return (rel) => {
    if (matchAny(rel, wt)) {
      const f = path.join(repo, full(rel))
      try { return fs.lstatSync(f).isFile() ? fs.readFileSync(f) : null } catch { return null }
    }
    const r = git(repo, ['cat-file', 'blob', `${rev}:${full(rel)}`], { allowFail: true })
    return r.status === 0 ? r.stdout : null
  }
}

function walkWorktree(repo, base, globs) {
  const root = path.join(repo, base)
  const out = new Map()
  const visit = (rel) => {
    const abs = path.join(root, rel)
    let st
    try { st = fs.lstatSync(abs) } catch { return }
    if (st.isSymbolicLink()) return out.set(rel, { kind: 'symlink', abs })
    if (st.isDirectory()) {
      if (path.basename(abs).toLowerCase() === '.git') return
      for (const n of fs.readdirSync(abs)) visit(rel ? rel + '/' + n : n)
      return
    }
    if (!matchAny(rel, globs)) return
    out.set(rel, st.isFile() ? { kind: 'file', abs } : { kind: 'special', abs })
  }
  for (const g of globs) visit(globPrefix(g))
  return out
}

// Build an isolated, read-only candidate in outDir/files. Returns manifest data + path findings.
function buildSnapshot(policy, outDir) {
  const repo = path.resolve(policy.source.repo)
  if (git(repo, ['rev-parse', '--git-dir'], { allowFail: true }).status !== 0) throw new UsageError(`source.repo is not a git repository: ${repo}`)
  const rev = git(repo, ['rev-parse', '--verify', `${policy.source.revision || 'HEAD'}^{commit}`]).stdout.toString().trim()
  const base = (policy.source.base || '').replace(/\/+$/, '')
  const wt = policy.source.worktreePaths || []
  const findings = []
  const fail = (file, message) => findings.push({ check: 'paths', status: 'FAIL', file, message })

  // Dirty state as Git itself judges it (avoids false positives from line-ending conversion).
  const status = git(repo, ['status', '--porcelain=v1', '-z', '--untracked-files=all']).stdout.toString().split('\0').filter(Boolean)
  const changed = new Set()
  for (let i = 0; i < status.length; i++) {
    const line = status[i]
    if (/^[RC]/.test(line)) i++ // rename/copy: the next record is the original path
    const p = line.slice(3)
    if (!base || p.startsWith(base + '/')) changed.add(base ? p.slice(base.length + 1) : p)
  }

  // Candidate entries from the pinned revision...
  const entries = new Map()
  const tree = git(repo, ['ls-tree', '-r', '-z', '--full-tree', rev]).stdout.toString().split('\0').filter(Boolean)
  for (const line of tree) {
    const [meta, p] = [line.slice(0, line.indexOf('\t')), line.slice(line.indexOf('\t') + 1)]
    const [mode, , oid] = meta.split(' ')
    if (base && !p.startsWith(base + '/')) continue
    const rel = base ? p.slice(base.length + 1) : p
    if (matchAny(rel, wt)) continue // the worktree is authoritative for these paths
    entries.set(rel, { from: 'HEAD', mode, oid })
  }
  // ...overlaid with explicitly opted-in working-tree paths.
  for (const [rel, w] of walkWorktree(repo, base, wt)) entries.set(rel, { from: 'worktree', ...w })

  const files = []
  const excluded = []
  const lower = new Map()
  const filesDir = path.join(outDir, 'files')
  const blobs = []

  for (const [rel, e] of [...entries].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const ex = (policy.exclude || []).find((x) => matchAny(rel, [x.glob]))
    if (ex) { excluded.push({ path: rel, reason: ex.reason, rule: ex.glob }); continue }
    if (!matchAny(rel, policy.include)) { excluded.push({ path: rel, reason: 'not in allowlist' }); continue }
    const prob = pathProblem(rel)
    if (prob) { fail(rel, `unsafe path: ${prob}`); continue }
    const key = rel.toLowerCase()
    if (lower.has(key)) { fail(rel, `case collision with ${lower.get(key)}`); continue }
    lower.set(key, rel)

    if (e.from === 'HEAD' && e.mode === '120000') {
      const target = git(repo, ['cat-file', 'blob', e.oid]).stdout.toString()
      fail(rel, symlinkVerdict(rel, target))
      continue
    }
    if (e.from === 'HEAD' && e.mode === '160000') { fail(rel, 'submodule (gitlink): contents are not part of this repository and are not published'); continue }
    if (e.kind === 'symlink') {
      let target = ''
      try { target = fs.readlinkSync(e.abs) } catch {}
      let real = null
      try { real = fs.realpathSync(e.abs) } catch {}
      const root = path.join(repo, base)
      const escapes = !real || path.relative(fs.realpathSync(root), real).startsWith('..') || path.isAbsolute(path.relative(fs.realpathSync(root), real))
      fail(rel, escapes ? 'symlink or junction escapes the source root' : `symlink or junction inside root (${path.basename(target)}); links are not published`)
      continue
    }
    if (e.kind === 'special') { fail(rel, 'unexpected file type (not a regular file)'); continue }
    blobs.push({ rel, e })
  }

  // Read committed contents in one batch.
  const heads = blobs.filter((b) => b.e.from === 'HEAD')
  const content = new Map()
  if (heads.length) {
    const out = git(repo, ['cat-file', '--batch'], { input: heads.map((b) => b.e.oid).join('\n') + '\n' }).stdout
    let off = 0
    for (const b of heads) {
      const nl = out.indexOf(10, off)
      const size = Number(out.subarray(off, nl).toString().split(' ')[2])
      content.set(b.rel, out.subarray(nl + 1, nl + 1 + size))
      off = nl + 1 + size + 1
    }
  }

  for (const { rel, e } of blobs) {
    const buf = e.from === 'HEAD' ? content.get(rel) : fs.readFileSync(e.abs)
    if (buf.length > MAX_FILE) { fail(rel, `file is ${buf.length} bytes; GitHub rejects files over 100 MiB`); continue }
    const dest = path.join(filesDir, ...rel.split('/'))
    fs.mkdirSync(path.dirname(dest), { recursive: true })
    fs.writeFileSync(dest, buf)
    fs.chmodSync(dest, 0o444)
    files.push({
      path: rel,
      size: buf.length,
      sha256: sha256(buf),
      mode: e.from === 'HEAD' && e.mode === '100755' ? '100755' : '100644',
      source: e.from,
      ...(e.from === 'HEAD' && changed.has(rel) ? { worktreeDiffers: true } : {}),
    })
  }

  const ignoredChanges = [...changed].filter((p) => !files.some((f) => f.path === p && f.source === 'worktree'))
  return {
    files,
    excluded,
    findings,
    source: { repo, base, revision: rev, revisionSpec: policy.source.revision || 'HEAD', dirty: changed.size > 0, changedPaths: changed.size, uncommittedChangesNotIncluded: ignoredChanges.length, worktreePaths: wt },
    read: sourceReader({ ...policy, source: { ...policy.source, repo } }, rev),
  }
}

function symlinkVerdict(rel, target) {
  if (target.startsWith('/') || /^[a-z]:/i.test(target) || target.includes('\\')) return 'symlink escapes the source root (absolute target)'
  const parts = [...rel.split('/').slice(0, -1), ...target.split('/')]
  let depth = 0
  for (const s of parts) { if (s === '..') depth--; else if (s && s !== '.') depth++; if (depth < 0) return 'symlink escapes the source root' }
  return 'symlink inside root; links are not published'
}

module.exports = { CHECK_IDS, validatePolicy, pathProblem, buildSnapshot, symlinkVerdict }
