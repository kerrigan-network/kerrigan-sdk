/// Kerrigan Sapling fee calculation.
///
/// Fee formula:
/// ```text
/// total = 10,000 + (nSpends × 5,000) + (nOutputs × 5,000)
/// ```
///
/// All values in satoshis (1 KRGN = 100,000,000 sat).
/// Base fee for any Sapling transaction (0.0002 KRGN).
pub const SAPLING_BASE_FEE: u64 = 20_000;

/// Additional fee per Sapling spend (input).
pub const SAPLING_PER_SPEND_FEE: u64 = 5_000;

/// Additional fee per Sapling output.
pub const SAPLING_PER_OUTPUT_FEE: u64 = 5_000;

/// Calculate the Sapling transaction fee for the given component counts.
pub fn sapling_fee(num_spends: usize, num_outputs: usize) -> u64 {
    SAPLING_BASE_FEE
        + (num_spends as u64 * SAPLING_PER_SPEND_FEE)
        + (num_outputs as u64 * SAPLING_PER_OUTPUT_FEE)
}

/// Calculate fee for a simple shield-to-shield send (1 change output).
///
/// `num_spends` notes consumed → 2 outputs (payment + change).
pub fn shield_send_fee(num_spends: usize) -> u64 {
    sapling_fee(num_spends, 2)
}

/// Calculate fee for a shielding transaction (transparent → sapling).
///
/// Transparent inputs don't count in the Sapling fee formula —
/// only the Sapling output side matters.
pub fn shield_fee(num_outputs: usize) -> u64 {
    sapling_fee(0, num_outputs)
}

/// Calculate fee for an unshielding transaction (sapling → transparent).
///
/// `num_spends` sapling notes → 1 sapling change output + 1 transparent output.
/// The transparent output doesn't count in the Sapling fee.
pub fn unshield_fee(num_spends: usize) -> u64 {
    sapling_fee(num_spends, 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fee_only() {
        assert_eq!(sapling_fee(0, 0), 20_000);
    }

    #[test]
    fn one_spend_one_output() {
        // 20000 + 5000 + 5000 = 30000
        assert_eq!(sapling_fee(1, 1), 30_000);
    }

    #[test]
    fn typical_shield_send() {
        // 1 spend, 2 outputs (payment + change)
        // 20000 + 5000 + 10000 = 35000
        assert_eq!(shield_send_fee(1), 35_000);
    }

    #[test]
    fn multi_spend_shield_send() {
        // 3 spends, 2 outputs
        // 20000 + 15000 + 10000 = 45000
        assert_eq!(shield_send_fee(3), 45_000);
    }

    #[test]
    fn shield_fee_one_output() {
        // 0 spends, 1 output
        // 20000 + 0 + 5000 = 25000
        assert_eq!(shield_fee(1), 25_000);
    }

    #[test]
    fn unshield_fee_one_spend() {
        // 1 spend, 1 sapling output (change)
        // 20000 + 5000 + 5000 = 30000
        assert_eq!(unshield_fee(1), 30_000);
    }

    #[test]
    fn max_spends_no_overflow() {
        let fee = sapling_fee(500, 500);
        assert_eq!(fee, 20_000 + 500 * 5_000 + 500 * 5_000);
    }
}
