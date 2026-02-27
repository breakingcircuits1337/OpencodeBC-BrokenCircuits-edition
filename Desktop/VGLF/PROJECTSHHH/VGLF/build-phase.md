# /build-phase [phase-number] — Build and Verify a VGLF Phase

Builds the specified phase, runs its tests, then triggers the security-auditor.

## Usage
```
/build-phase 1   # Build spinal-cord
/build-phase 2   # Build vortex-sink
/build-phase 3   # Build pqc-keymgmt
/build-phase 4   # Build cortex-engine
/build-phase 5   # Build tier0-ratelimit
/build-phase 6   # Full integration + canary
```

## Steps to execute:

1. Run the appropriate build command for the phase:
   - Phase 1: `cargo build --release -p spinal-cord`
   - Phase 2: `cargo build --release -p vortex-sink`
   - Phase 3: `cargo build --release -p pqc-keymgmt`
   - Phase 4: `python -m pytest cortex-engine/tests/ -v`
   - Phase 5: `sudo nft -cf tier0-ratelimit/nftables.conf` (config check only)
   - Phase 6: `cargo test --workspace && python -m pytest tests/ -v`

2. Run the phase-specific tests

3. Spawn **security-auditor** subagent to review new code in the phase directory

4. Report: build status + test results + security findings
