/// Transaction fee estimation for Kerrigan Network.
///
/// Calculates fees based on estimated virtual transaction size (vsize) and a
/// configurable fee rate.  The size model is split by component type so that
/// future transaction formats (e.g., Sapling shielded inputs/outputs) can be
/// added without rewriting the core estimator.
///
/// # Size model (transparent v1)
///
/// | Component           | Bytes   | Notes                                     |
/// |---------------------|---------|-------------------------------------------|
/// | Overhead            | 10      | version(4) + locktime(4) + varint(~2)     |
/// | Transparent input   | 148     | outpoint(36) + scriptSig(~107) + seq(4) + varint(1) |
/// | Transparent output  | 34      | value(8) + scriptPubKey(25) + varint(1)   |
///
/// The default fee rate is 10 sat/byte ([`DEFAULT_FEE_PER_BYTE`]).
use crate::params;
use crate::script::ScriptType;

// ---------------------------------------------------------------------------
// Size constants (by component type)
// ---------------------------------------------------------------------------

/// Fixed per-transaction overhead: version(4) + locktime(4) + input/output count varints(~2).
pub const TX_OVERHEAD_BYTES: usize = 10;

/// Size of one transparent P2PKH input (worst-case with 72-byte DER signature).
///
/// Breakdown: outpoint(36) + scriptSig varint(1) + scriptSig(109) + sequence(4) = 148 (conservative; see comment below).
// scriptSig detail: 1 (sig push) + 73 (DER sig + sighash) + 1 (pubkey push) + 33 (pubkey) = 108, plus 1-byte varint = 109.
pub const P2PKH_INPUT_BYTES: usize = 148;

/// Size of one transparent output (P2PKH):
/// value(8) + scriptPubKey varint(1) + scriptPubKey(25) = 34.
pub const P2PKH_OUTPUT_BYTES: usize = 34;

/// Size of one transparent output (P2SH):
/// value(8) + scriptPubKey varint(1) + scriptPubKey(23) = 32.
pub const P2SH_OUTPUT_BYTES: usize = 32;

// Future: add constants for shielded components.
// pub const SAPLING_INPUT_BYTES: usize = 384;
// pub const SAPLING_OUTPUT_BYTES: usize = 948;

// ---------------------------------------------------------------------------
// Component-based size estimation
// ---------------------------------------------------------------------------

/// A breakdown of transaction components for fee estimation.
///
/// Each field represents a count of that component type. Future transaction
/// formats extend this struct with new fields (e.g., `sapling_inputs`).
#[derive(Debug, Clone, Default)]
pub struct TxComponents {
    /// Number of transparent P2PKH inputs being spent.
    pub transparent_inputs: usize,
    /// Number of transparent outputs. Each entry is the output's script type.
    pub transparent_outputs: Vec<ScriptType>,

    // Future fields:
    // pub sapling_inputs: usize,
    // pub sapling_outputs: usize,
}

impl TxComponents {
    /// Create components for a simple transparent-only transaction.
    pub fn transparent(input_count: usize, output_types: Vec<ScriptType>) -> Self {
        Self {
            transparent_inputs: input_count,
            transparent_outputs: output_types,
        }
    }

    /// Estimate the total serialized transaction size in bytes.
    pub fn estimated_size(&self) -> usize {
        let inputs = self.transparent_inputs * P2PKH_INPUT_BYTES;
        let outputs: usize = self.transparent_outputs.iter().map(|st| {
            match st {
                ScriptType::P2PKH => P2PKH_OUTPUT_BYTES,
                ScriptType::P2SH => P2SH_OUTPUT_BYTES,
            }
        }).sum();
        TX_OVERHEAD_BYTES + inputs + outputs
    }
}

// ---------------------------------------------------------------------------
// Fee calculation
// ---------------------------------------------------------------------------

/// Estimate the fee for a transaction given its component breakdown.
///
/// `fee = estimated_size(components) × fee_per_byte`
pub fn estimate_fee(components: &TxComponents, fee_per_byte: u64) -> u64 {
    components.estimated_size() as u64 * fee_per_byte
}

/// Estimate the fee using the default fee rate ([`params::DEFAULT_FEE_PER_BYTE`]).
pub fn estimate_fee_default(components: &TxComponents) -> u64 {
    estimate_fee(components, params::DEFAULT_FEE_PER_BYTE)
}

/// Quick fee estimate for a simple transparent P2PKH-to-P2PKH transaction.
///
/// Useful when you know the number of inputs and outputs but don't need
/// the full [`TxComponents`] builder.
pub fn estimate_transparent_fee(input_count: usize, output_count: usize) -> u64 {
    let size = TX_OVERHEAD_BYTES + input_count * P2PKH_INPUT_BYTES + output_count * P2PKH_OUTPUT_BYTES;
    size as u64 * params::DEFAULT_FEE_PER_BYTE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Size estimation --

    #[test]
    fn size_single_input_single_output() {
        let comp = TxComponents::transparent(1, vec![ScriptType::P2PKH]);
        // 10 + 148 + 34 = 192
        assert_eq!(comp.estimated_size(), 192);
    }

    #[test]
    fn size_single_input_two_outputs() {
        // Typical send: one destination + one change output
        let comp = TxComponents::transparent(1, vec![ScriptType::P2PKH, ScriptType::P2PKH]);
        // 10 + 148 + 34 + 34 = 226
        assert_eq!(comp.estimated_size(), 226);
    }

    #[test]
    fn size_two_inputs_two_outputs() {
        let comp = TxComponents::transparent(2, vec![ScriptType::P2PKH, ScriptType::P2PKH]);
        // 10 + 2*148 + 2*34 = 374
        assert_eq!(comp.estimated_size(), 374);
    }

    #[test]
    fn size_p2sh_output_smaller() {
        let p2pkh = TxComponents::transparent(1, vec![ScriptType::P2PKH]);
        let p2sh = TxComponents::transparent(1, vec![ScriptType::P2SH]);
        // P2SH output is 2 bytes smaller (23-byte script vs 25-byte)
        assert_eq!(p2pkh.estimated_size() - p2sh.estimated_size(), 2);
    }

    #[test]
    fn size_mixed_outputs() {
        let comp = TxComponents::transparent(1, vec![ScriptType::P2PKH, ScriptType::P2SH]);
        // 10 + 148 + 34 + 32 = 224
        assert_eq!(comp.estimated_size(), 224);
    }

    #[test]
    fn size_no_inputs_no_outputs() {
        let comp = TxComponents::transparent(0, vec![]);
        assert_eq!(comp.estimated_size(), TX_OVERHEAD_BYTES);
    }

    #[test]
    fn size_many_inputs() {
        let comp = TxComponents::transparent(10, vec![ScriptType::P2PKH, ScriptType::P2PKH]);
        // 10 + 10*148 + 2*34 = 1558
        assert_eq!(comp.estimated_size(), 1558);
    }

    // -- Fee estimation --

    #[test]
    fn fee_default_rate() {
        let comp = TxComponents::transparent(1, vec![ScriptType::P2PKH, ScriptType::P2PKH]);
        // 226 bytes × 10 sat/byte = 2260 sat
        assert_eq!(estimate_fee_default(&comp), 2260);
    }

    #[test]
    fn fee_custom_rate() {
        let comp = TxComponents::transparent(1, vec![ScriptType::P2PKH, ScriptType::P2PKH]);
        // 226 bytes × 20 sat/byte = 4520
        assert_eq!(estimate_fee(&comp, 20), 4520);
    }

    #[test]
    fn fee_zero_rate() {
        let comp = TxComponents::transparent(5, vec![ScriptType::P2PKH]);
        assert_eq!(estimate_fee(&comp, 0), 0);
    }

    #[test]
    fn fee_quick_transparent() {
        // Quick helper matches TxComponents-based calculation for P2PKH-only
        let quick = estimate_transparent_fee(2, 2);
        let comp = TxComponents::transparent(2, vec![ScriptType::P2PKH, ScriptType::P2PKH]);
        assert_eq!(quick, estimate_fee_default(&comp));
    }

    // -- Dust threshold --

    #[test]
    fn minimum_fee_above_dust() {
        // Even a 1-in/1-out tx should have a fee well above 0
        let fee = estimate_transparent_fee(1, 1);
        assert!(fee > params::DUST_THRESHOLD, "Fee {fee} should exceed dust threshold");
    }

    // -- Consistency --

    #[test]
    fn fee_scales_linearly_with_inputs() {
        let fee1 = estimate_transparent_fee(1, 2);
        let fee2 = estimate_transparent_fee(2, 2);
        let fee3 = estimate_transparent_fee(3, 2);
        // Adding one input should add exactly P2PKH_INPUT_BYTES * fee_per_byte
        let input_cost = P2PKH_INPUT_BYTES as u64 * params::DEFAULT_FEE_PER_BYTE;
        assert_eq!(fee2 - fee1, input_cost);
        assert_eq!(fee3 - fee2, input_cost);
    }

    #[test]
    fn fee_scales_linearly_with_outputs() {
        let fee1 = estimate_transparent_fee(1, 1);
        let fee2 = estimate_transparent_fee(1, 2);
        let fee3 = estimate_transparent_fee(1, 3);
        let output_cost = P2PKH_OUTPUT_BYTES as u64 * params::DEFAULT_FEE_PER_BYTE;
        assert_eq!(fee2 - fee1, output_cost);
        assert_eq!(fee3 - fee2, output_cost);
    }
}
