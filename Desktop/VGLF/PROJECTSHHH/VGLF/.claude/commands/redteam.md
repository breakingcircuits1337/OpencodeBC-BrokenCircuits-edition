# /redteam — Run Full Red Team Check

Spawn the red-teamer and security-auditor subagents in parallel, then report combined findings.

Use the Task tool to run these **in parallel**:

1. **security-auditor** — Static analysis against all 14 red team findings
2. **red-teamer** — Active attack scenario simulation

After both complete, synthesize results:
- List all CRITICAL findings first (stop-the-line issues)
- Then HIGH, MEDIUM, LOW
- Give overall PASS/FAIL verdict
- If FAIL: list exact files and lines to fix before any merge

This command should be run:
- Before every PR merge to main
- Before any public release
- After any change to cortex-engine/, spinal-cord/src/crypto/, or ipc/
