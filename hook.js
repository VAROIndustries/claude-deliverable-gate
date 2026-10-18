#!/usr/bin/env node
'use strict'
// PreToolUse guard (ADVISORY): refuses Claude's own push/publish commands run against a registered deliverable
// source repository, steering them to `gate.js publish`. It only sees Claude's Bash/PowerShell tool calls, so a
// push from another terminal, an alias or a script bypasses it. Fails open on its own errors.
const fs = require('node:fs')
const path = require('node:path')
const { home, isInside } = require('./lib/util')

const PUBLISHING = /\bgit\b[^\n;|&]*\bpush\b|\bgh\s+(repo\s+(create|edit|sync)|release\s+create)\b/i

function decide(input) {
  const cmd = input?.tool_input?.command
  if (typeof cmd !== 'string' || !PUBLISHING.test(cmd)) return null
  const dir = path.join(home(), 'deliverables')
  if (!fs.existsSync(dir)) return null
  const norm = (s) => s.replace(/\\/g, '/').toLowerCase()
  for (const name of fs.readdirSync(dir)) {
    let repo
    try { repo = JSON.parse(fs.readFileSync(path.join(dir, name, 'policy.json'), 'utf8')).source.repo } catch { continue }
    if (!repo) continue
    const inCwd = input.cwd && isInside(input.cwd, repo)
    const r = norm(path.resolve(repo))
    const named = norm(cmd).includes(r) || norm(cmd).includes(r.replace(/^([a-z]):/, '/$1')) // C:/x or Git Bash /c/x
    if (inCwd || named) return `Deliverable Gate: ${repo} is the source of registered deliverable "${name}". Don't push or publish from it directly. Run the gate: check, get the user's explicit approval, then gate.js publish. (This guard is advisory and only covers Claude's tool calls.)`
  }
  return null
}

if (require.main === module) {
  let data = ''
  process.stdin.on('data', (c) => (data += c))
  process.stdin.on('end', () => {
    try {
      const reason = decide(JSON.parse(data))
      if (reason) process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }))
    } catch {}
  })
}

module.exports = { decide }
