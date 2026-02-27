#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
//! # pqc-keymgmt -- ML-DSA-65 Key Lifecycle Management for VGLF
//!
//! This crate implements Phase 3 of the VGLF build: key generation, storage,
//! rotation, model signing, and rule bundle signing using the ML-DSA-65
//! digital signature scheme (FIPS 204).
//!
//! # Module overview
//!
//! | Module          | Purpose                                              |
//! |-----------------|------------------------------------------------------|
//! | `keystore`      | `KeyStore` trait + impls (File dev, Vault/TPM stubs) |
//! | `lifecycle`     | Key generation with metadata, rotation, key ID track |
//! | `model_signer`  | ONNX model SHA3-256 hash + ML-DSA-65 signing (RT-C04)|
//! | `bundle_signer` | Rule bundle signing for IPC protocol                 |
//!
//! # Security model
//!
//! - All key material is zeroized on drop via the `zeroize` crate.
//! - The `FileKeyStore` is for **development only** -- it logs a warning on
//!   construction and must never be used in production deployments.
//! - Production deployments must use TPM 2.0 (`TpmKeyStore`) or `HashiCorp`
//!   Vault transit (`VaultKeyStore`), both currently stubbed.
//! - No flat-file PQC private keys in production (Security Invariant #7).
//! - All algorithm references flow through the `DigitalSignature` crypto
//!   agility trait from `spinal-cord` -- never hardcoded.

pub mod bundle_signer;
pub mod keystore;
pub mod lifecycle;
pub mod model_signer;
