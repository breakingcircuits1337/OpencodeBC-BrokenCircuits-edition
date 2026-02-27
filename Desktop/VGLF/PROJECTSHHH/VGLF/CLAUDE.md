# VGLF — Vortex-Gated LLM Firewall
## Claude Code Project Constitution v1.0 | BreakingCircuits.com

> This is a **defense tool for municipalities and critical infrastructure**.
> Every line of code is a potential attack surface. Think like a red teamer, build like a defender.

---

## 🏗️ PROJECT STRUCTURE

```
vglf/
├── CLAUDE.md                    ← YOU ARE HERE
├── .claude/
│   ├── settings.json            ← permissions, hooks, model config
│   ├── commands/                ← slash commands
│   └── agents/                  ← subagent definitions
├── spinal-cord/                 ← Rust: Tier 1 proxy + ONNX inference
├── cortex-engine/               ← Python: Tier 3 LLM analysis
├── vortex-sink/                 ← Rust: Tier 2 Arrow→Vortex persistence
├── pqc-keymgmt/                 ← Rust: ML-DSA key lifecycle
├── tier0-ratelimit/             ← nftables: Tier 0b flood mitigation
└── tests/                       ← red-team regression + canary suites
```

**Monorepo rule:** Each top-level crate/package is a separate Cargo workspace member or Python package. Never cross-import between tiers at the source level — they communicate only via typed IPC (Unix socket, Arrow IPC, or PQC-signed bundles).

---

## ⚡ BUILD COMMANDS

```bash
# Full workspace build (Rust)
cargo build --release --workspace

# Run all tests including security regression suite
cargo test --workspace && python -m pytest cortex-engine/tests/ -v

# Build + verify ONNX model hash
cargo run --bin vglf-verify -- --model models/reflex.onnx

# Load nftables Tier 0b rules (requires root)
sudo nft -f tier0-ratelimit/nftables.conf

# Start Cortex (local LLM required at localhost:11434)
python -m cortex.main --config config/cortex.toml

# Run red team regression suite
cargo test --test red_team -- --test-threads=1
python -m pytest tests/red-team/ -v --tb=short

# Run canary model validation (must pass before any model promotion)
python tests/canary/validate.py --model models/reflex.onnx --threshold 0.95
```

---

## 🔒 SECURITY INVARIANTS — NEVER VIOLATE

These are absolute. No argument, no exception, no "it's just a test":

1. **LLM output NEVER reaches subprocess, exec, or eval** — route all rule updates through the typed Rust IPC socket at `/var/run/vglf/rules.sock`
2. **DuckDB ALWAYS runs read-only** — `duckdb.connect(read_only=False)` with `SET disabled_filesystems` — never allow write access from the Cortex process
3. **All LLM-analyzed data is wrapped in `DATA_WRAPPER` delimiters** — payload content is never interpolated into instruction text
4. **ONNX model loads require SHA-256 hash + ML-DSA-65 signature verification** — fail hard on mismatch, never soft-fail
5. **Sacrosanct IPs (SCADA gateway, mgmt network, 127.0.0.1) cannot be blacklisted** — enforced by the Rust IPC handler, not the Python Cortex
6. **LOCAL_LLM_URL must resolve to localhost/private range by default** — cloud endpoints require explicit `--allow-cloud` flag and operator consent
7. **No flat-file PQC private keys in the repo** — TPM 2.0 or Vault transit; key material never committed to git
8. **IPv6 parity** — every IPv4 code path must have an IPv6 equivalent; use 128-bit address types

---

## 🦀 RUST CODING STANDARDS

- **Edition:** Rust 2021, MSRV 1.82+
- **Async runtime:** Tokio only — never `std::thread::sleep` in async context
- **Rayon ↔ Tokio boundary:** always use `crossbeam::channel` — never `tokio::mpsc::blocking_send` from Rayon threads (deadlock risk, see RT-H03)
- **Error handling:** `anyhow` for application errors, `thiserror` for library errors — no `.unwrap()` in production paths, `expect("reason")` allowed in tests only
- **Crypto:** `aws-lc-rs` for ML-KEM/ML-DSA — never `liboqs-rust` in production (has "DO NOT USE IN PRODUCTION" warning as of 2026)
- **No unsafe blocks** without a `// SAFETY:` comment explaining exactly why it is safe and reviewed by the security agent
- **Clippy:** `#![deny(clippy::all, clippy::pedantic)]` in every crate — CI blocks on warnings

```toml
# Cargo.toml workspace deps — use these, not random crates
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
rayon = "1"
crossbeam = "0.8"
anyhow = "1"
thiserror = "1"
aws-lc-rs = "1"
ort = "2"                    # ONNX Runtime
apache-arrow = "52"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "1"
tracing-subscriber = "1"
ipnetwork = "0.20"           # IPv4+IPv6 CIDR handling
```

---

## 🐍 PYTHON CODING STANDARDS

- **Version:** Python 3.11+ (3.12 preferred)
- **Type hints:** required on all public functions — `mypy --strict` must pass
- **Input validation:** ALL LLM output is validated with `ipaddress.ip_address()` before any action — never trust string content from the model
- **No `subprocess` with shell=True** — ever. If a Rust binary must be called, use the IPC socket instead
- **DuckDB queries:** parameterized only — `con.execute(query, [param])` — never f-strings or `.format()` in SQL
- **Dependencies:** pinned in `requirements.txt` with hashes — `pip install --require-hashes`
- **Secrets:** never in source — load from environment or TPM/Vault

---

## 🔐 PQC STANDARDS

| Use Case | Algorithm | Library | Notes |
|---|---|---|---|
| Key exchange | ML-KEM-768 + X25519 hybrid | `aws-lc-rs` | FIPS 203; hybrid for downgrade resistance |
| Signatures | ML-DSA-65 | `aws-lc-rs` | FIPS 204; signs all rule bundles + model files |
| Hashing | SHA3-256 | `sha3` crate | Merkle chain, model pin, log integrity |
| Symmetric | AES-256-GCM | `aws-lc-rs` | At-rest Vortex encryption; already PQ-secure |

**Crypto agility:** all algorithm references go through traits in `spinal-cord/src/crypto/traits.rs` — never hardcode algorithm names outside that module.

---

## 🧪 TESTING REQUIREMENTS

- **Before ANY PR merge:** `cargo test --workspace` + `pytest cortex-engine/tests/` both green
- **Before model promotion:** canary suite must pass with F1 ≥ 0.95 — `python tests/canary/validate.py`
- **Red team regression:** `cargo test --test red_team` must be run and green — covers RT-C01 through RT-H04
- **NIST KAT vectors:** ML-KEM and ML-DSA test vectors in `tests/pqc-vectors/` — must pass on every commit touching crypto code
- **Sacrosanct IP test:** any commit touching the IPC handler must run `cargo test test_sacrosanct_ip_cannot_be_blocked`
- **IPv6 parity:** every new IPv4 test gets a corresponding IPv6 test — enforce via CI

---

## 🚩 CLI FLAGS & RUNTIME CONFIG

| Flag | Default | Description |
|---|---|---|
| `--config` | `config/vglf.toml` | Main config file path |
| `--model` | `models/reflex.onnx` | ONNX model path (hash-verified at load) |
| `--ipc-socket` | `/var/run/vglf/rules.sock` | Cortex→Rust rule update socket |
| `--allow-cloud` | `false` | Allow LLM endpoint outside localhost (requires explicit consent) |
| `--dry-run` | `false` | Analyze and log, never apply rules to nftables |
| `--log-level` | `info` | `trace/debug/info/warn/error` |
| `--sacrosanct` | `config/sacrosanct.toml` | Read-only list of IPs that can never be blocked |
| `--canary-validate` | (subcommand) | Run model canary before starting; exit if F1 < threshold |

---

## 🤖 AGENT DELEGATION STRATEGY

This project uses **4 specialized subagents** + the main orchestrator. Use `Task(...)` to spawn them in parallel for independent work, sequentially for dependent work.

### When to delegate vs. stay in main context:

| Task Type | Use Main Agent | Use Subagent |
|---|---|---|
| Architecture decisions | ✅ | — |
| Writing new Rust crates | ✅ | — |
| Security review of new code | — | ✅ `security-auditor` |
| Red team regression run | — | ✅ `red-teamer` |
| Cortex Python implementation | — | ✅ `cortex-builder` |
| PQC crypto implementation | — | ✅ `pqc-specialist` |
| Cross-tier integration | ✅ | — |

See `.claude/agents/` for subagent definitions.

---

## 📁 FILE RULES

- **Never commit:** `.env`, `*.pem`, `*.key`, `*.p8`, model weights without hash sidecar, `CLAUDE.local.md`
- **Always commit:** `requirements.txt` with hashes, `Cargo.lock`, `config/*.toml.example` (no secrets), test vectors
- **Model files:** stored in `models/` with a `.sha256` sidecar — CI verifies hash on every build
- **Secrets go in:** TPM 2.0 (prod), Vault transit (staging), `.env.local` gitignored (dev only)

---

## 🚀 PHASE BUILD ORDER

Follow this order — later phases depend on earlier ones:

**Phase 0 (CRITICAL — do before anything goes public):**
Fix RT-C01, RT-C02, RT-C03, RT-C04. All four. No exceptions.

**Phase 1:** `spinal-cord` — Rust proxy + ONNX + crossbeam + PQC traits
**Phase 2:** `vortex-sink` — Arrow→Vortex + Merkle chain + syslog mirror
**Phase 3:** `pqc-keymgmt` — TPM/Vault key lifecycle + ML-DSA signing
**Phase 4:** `cortex-engine` — Hardened Python Cortex + deterministic validator
**Phase 5:** `tier0-ratelimit` — nftables baseline + SmartNIC docs
**Phase 6:** Integration + red team regression + canary + compliance docs
**Phase 7:** Public release under Apache 2.0

---

## ⚠️ KNOWN LANDMINES

- **Rayon + Tokio:** `rayon::spawn` + `blocking_send` = deadlock under load → always use `crossbeam::channel`
- **DuckDB file I/O:** `read_blob`, `httpfs`, `getenv` are loaded by default — disable them explicitly
- **liboqs-rust:** has a hard "DO NOT USE IN PRODUCTION" warning — use `aws-lc-rs` instead
- **IPv6 gaps:** every filter, map, schema, and feature vector defaults to IPv4 if you don't explicitly design for IPv6
- **LLM temperature:** Cortex must use `temperature=0.0` and `max_tokens=10` for block/allow decisions — never leave defaults
- **Sacrosanct list:** must be populated with SCADA/PLC/HMI addresses before first production run

---

## 📚 KEY REFERENCES

- Red Team Findings: `docs/RED-TEAM-FINDINGS.md` (all 14 findings + fixes)
- Threat Model: `docs/THREAT-MODEL.md`
- CNSA 2.0 Compliance: `docs/CNSA-2.0-COMPLIANCE.md`
- OT/ICS Deployment: `docs/OT-ICS-DEPLOYMENT.md`
- Full Architecture Plan: `VGLF_RedTeam_FinalPlan_2026.docx`

---

*VGLF | BreakingCircuits.com | Apache 2.0 | February 2026*
