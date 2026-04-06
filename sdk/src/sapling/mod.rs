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

pub mod network;
pub mod keys;
pub mod tree;
pub mod notes;
