'use strict'
// Small shared helpers: hashing, canonical JSON, globs, process runners, storage paths.
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex')
// Git blob id of raw bytes (what `git hash-object --no-filters` prints).
const gitBlobId = (buf) => crypto.createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex')

function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']'
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}'
  return JSON.stringify(v)
}

// Glob -> RegExp. Supports `**`, `*`, `?`. Case-insensitive so an exclusion can't be dodged by case.
function globRe(glob) {
  let re = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === '*' && glob[i + 1] === '*') {
      i++
      if (glob[i + 1] === '/') { i++; re += '(?:.*/)?' } else re += '.*'
    } else if (c === '*') re += '[^/]*'
    else if (c === '?') re += '[^/]'
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp('^' + re + '$', 'i')
}
const matchAny = (rel, globs) => globs.find((g) => globRe(typeof g === 'string' ? g : g.glob).test(rel))

// Static directory prefix of a glob ("docs/export/**" -> "docs/export").
function globPrefix(glob) {
  const out = []
  for (const s of glob.split('/')) { if (/[*?]/.test(s)) break; out.push(s) }
  return out.join('/')
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { maxBuffer: 1 << 30, windowsHide: true, ...opts })
  return { status: r.error ? -1 : r.status, stdout: r.stdout ?? Buffer.alloc(0), stderr: (r.stderr ?? '').toString(), error: r.error }
}
function git(repo, args, opts = {}) {
  const r = run('git', ['-C', repo, '-c', 'core.quotepath=off', ...args], opts)
  if (r.status !== 0 && !opts.allowFail) throw new Error(`git ${args[0]} failed: ${r.stderr.trim() || r.error?.message}`)
  return r
}

const home = () => process.env.DELIVERABLE_GATE_HOME || path.join(os.homedir(), '.claude', 'deliverable-gate')
const deliverableDir = (name) => {
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(name || '')) throw new UsageError(`invalid deliverable name: ${JSON.stringify(name)}`)
  return path.join(home(), 'deliverables', name)
}
const samePath = (a, b) => path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase()
const isInside = (child, parent) => {
  const rel = path.relative(path.resolve(parent).toLowerCase(), path.resolve(child).toLowerCase())
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'))
const writeJson = (f, v) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, JSON.stringify(v, null, 2) + '\n') }

// Report-safe text: no newlines/backticks/pipes from file names or link targets leak into Markdown structure.
const safe = (s) => String(s).replace(/[\r\n\t]/g, ' ').replace(/[`|]/g, '?').slice(0, 300)

class UsageError extends Error {}

// Remove a tree that may contain read-only files (snapshots are made read-only).
function rmTree(dir) {
  if (!fs.existsSync(dir)) return
  for (const e of fs.readdirSync(dir, { recursive: true })) {
    try { fs.chmodSync(path.join(dir, e), 0o755) } catch {}
  }
  fs.rmSync(dir, { recursive: true, force: true })
}

module.exports = { sha256, gitBlobId, canonical, globRe, matchAny, globPrefix, run, git, home, deliverableDir, samePath, isInside, readJson, writeJson, safe, UsageError, rmTree }
