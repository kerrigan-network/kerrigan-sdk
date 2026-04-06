/// Sapling shielded transaction support for the Kerrigan Network.
///
/// # Modules
///
/// | Module | Purpose |
/// |--------|---------|
/// | [`network`] | Kerrigan Sapling network constants (`KerriganMainNetwork`) |
/// | [`keys`] | ZIP32 key derivation, encoding, payment addresses |
/// | [`tree`] | Commitment tree operations, hex serialization, witnesses |
/// | [`notes`] | Note types, decryption, transaction processing |
/// | [`fees`] | Sapling fee calculation (Kerrigan formula) |
/// | [`prover`] | Proving parameter types and SHA-256 verification |
/// | [`builder`] | Sapling transaction construction and signing |

pub mod network;
pub mod keys;
pub mod tree;
pub mod notes;
pub mod fees;
pub mod prover;
pub mod builder;
pub mod kerrigan_tx;
pub mod sync;
