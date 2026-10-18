#!/usr/bin/env node
'use strict'
// Deliverable Gate CLI. Report-only unless an explicit approval exists for the exact candidate and destination.
const gate = require('./lib/gate')
const { UsageError } = require('./lib/util')

const USAGE = `usage:
  gate.js init <name> --repo <path>          create a policy skeleton (local, outside the repo)
  gate.js check <name>                       build a candidate snapshot, run checks, write manifest + report
  gate.js approve <name> --candidate <id> --destination "<identity>" [--accept-incomplete a,b]
  gate.js publish <name> --candidate <id>    publish an approved candidate (snapshot mode, GitHub)
  gate.js status [<name>]                    list deliverables, candidates, approvals, publications
  gate.js verify <name> --candidate <id>     re-hash a candidate snapshot against its manifest
  gate.js clean <name> [--keep N] [--all]    delete old candidates (retention)
exit codes: 0 ok/READY, 1 BLOCKED or refused, 2 INCOMPLETE, 64 usage error, 70 internal error`

function main(argv) {
  const [cmd, name] = argv
  const flag = (f) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : undefined }
  const need = (f) => { const v = flag(f); if (!v) throw new UsageError(`${f} is required`); return v }
  switch (cmd) {
    case 'init': {
      console.log(`policy written: ${gate.init(name, need('--repo'))}\nEdit it before running check. Nothing in the source repository was touched.`)
      return 0
    }
    case 'check': {
      const r = gate.check(name)
      console.log(r.md)
      console.log(`report:   ${r.dir}\\report.md\nmanifest: ${r.dir}\\manifest.json`)
      return { READY: 0, INCOMPLETE: 2, BLOCKED: 1 }[r.verdict]
    }
    case 'approve': {
      const accept = (flag('--accept-incomplete') || '').split(',').filter(Boolean)
      const a = gate.approve(name, need('--candidate'), { destination: need('--destination'), acceptIncomplete: accept })
      console.log(`approved candidate ${a.candidateId} for ${a.destination}\napproval sha256:${a.approvalHash}${a.acceptedIncomplete.length ? `\naccepted as incomplete: ${a.acceptedIncomplete.join(', ')}` : ''}\nThe approval becomes invalid if the snapshot, policy, destination or destination branch changes.`)
      return 0
    }
    case 'publish': {
      const p = gate.publish(name, need('--candidate'))
      console.log(p.pushed ? `published ${p.candidateId} to ${p.destination}\ncommit ${p.commit} (author ${p.author})\n${p.identityGuardSummary}` : p.message)
      return 0
    }
    case 'status': {
      console.log(JSON.stringify(name ? gate.status(name) : gate.list(), null, 2))
      return 0
    }
    case 'verify': {
      const { problems } = gate.verifyCandidate(name, need('--candidate'))
      console.log(problems.length ? `MODIFIED:\n  ${problems.join('\n  ')}` : 'intact: snapshot matches its manifest')
      return problems.length ? 1 : 0
    }
    case 'clean': {
      const r = gate.clean(name, { keep: Number(flag('--keep') ?? 3), all: argv.includes('--all') })
      console.log(`removed ${r.removed.length} candidate(s); kept ${r.kept.join(', ') || 'none'}`)
      return 0
    }
    default:
      console.error(USAGE)
      return 64
  }
}

try {
  process.exitCode = main(process.argv.slice(2))
} catch (e) {
  if (e instanceof UsageError) { console.error(`error: ${e.message}\n\n${USAGE}`); process.exitCode = 64 }
  else if (e instanceof gate.Refusal) { console.error(`REFUSED: ${e.message}`); process.exitCode = 1 }
  else { console.error(`deliverable-gate internal error: ${e.message}`); process.exitCode = 70 }
}
