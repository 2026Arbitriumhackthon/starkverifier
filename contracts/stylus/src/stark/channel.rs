//! Fiat-Shamir Channel using Poseidon Hash
//!
//! Implements a deterministic transcript for non-interactive proofs.
//! All randomness is derived from Poseidon hashing of the protocol transcript.

use alloy_primitives::U256;

use crate::field::Fp;
use crate::poseidon::PoseidonHasher;

/// Fiat-Shamir channel for deterministic challenge generation.
pub struct Channel {
    /// Current channel state
    state: Fp,
    /// Counter for unique challenge derivation
    counter: u64,
}

impl Channel {
    /// Create a new channel with an initial seed.
    pub fn new(seed: Fp) -> Self {
        Channel {
            state: seed,
            counter: 0,
        }
    }

    /// Commit a value to the channel transcript.
    pub fn commit(&mut self, value: Fp) {
        self.state = PoseidonHasher::hash_two(self.state, value);
        self.counter = 0;
    }

    /// Draw a random field element from the channel.
    pub fn draw_felt(&mut self) -> Fp {
        let counter_fp = Fp::from_u256(U256::from(self.counter));
        let challenge = PoseidonHasher::hash_two(self.state, counter_fp);
        self.counter += 1;
        challenge
    }

    /// Draw multiple random query indices from the channel (test only).
    #[cfg(test)]
    pub fn draw_queries(&mut self, count: usize, domain_size: usize) -> alloc::vec::Vec<usize> {
        let mut indices = alloc::vec::Vec::with_capacity(count);

        while indices.len() < count {
            let raw = self.draw_felt();
            let raw_u256 = raw.to_u256();
            let mask = U256::from((domain_size - 1) as u64);
            let index = (raw_u256 & mask).as_limbs()[0] as usize;

            if !indices.contains(&index) {
                indices.push(index);
            }
        }

        indices
    }

    /// Draw query indices without Vec allocation (no_std compatible).
    pub fn draw_queries_into(&mut self, output: &mut [usize], count: usize, domain_size: usize) -> usize {
        let count = core::cmp::min(count, output.len());
        let mut written = 0;

        while written < count {
            let raw = self.draw_felt();
            let raw_u256 = raw.to_u256();
            let mask = U256::from((domain_size - 1) as u64);
            let index = (raw_u256 & mask).as_limbs()[0] as usize;

            let mut unique = true;
            for i in 0..written {
                if output[i] == index {
                    unique = false;
                    break;
                }
            }

            if unique {
                output[written] = index;
                written += 1;
            }
        }

        written
    }

    /// Get current state
    pub fn state(&self) -> Fp {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_deterministic() {
        let seed = Fp::from_u256(U256::from(42u64));

        let mut ch1 = Channel::new(seed);
        ch1.commit(Fp::from_u256(U256::from(100u64)));
        let v1 = ch1.draw_felt();

        let mut ch2 = Channel::new(seed);
        ch2.commit(Fp::from_u256(U256::from(100u64)));
        let v2 = ch2.draw_felt();

        assert_eq!(v1, v2, "Channel not deterministic");
    }

    #[test]
    fn test_channel_different_commits_different_output() {
        let seed = Fp::from_u256(U256::from(42u64));

        let mut ch1 = Channel::new(seed);
        ch1.commit(Fp::from_u256(U256::from(100u64)));
        let v1 = ch1.draw_felt();

        let mut ch2 = Channel::new(seed);
        ch2.commit(Fp::from_u256(U256::from(200u64)));
        let v2 = ch2.draw_felt();

        assert_ne!(v1, v2, "Different commits should produce different output");
    }

    #[test]
    fn test_draw_felt_unique() {
        let mut ch = Channel::new(Fp::from_u256(U256::from(1u64)));
        ch.commit(Fp::ZERO);

        let v1 = ch.draw_felt();
        let v2 = ch.draw_felt();
        let v3 = ch.draw_felt();

        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_draw_felt_in_field() {
        use crate::poseidon::field::BN254_PRIME;
        let mut ch = Channel::new(Fp::from_u256(U256::from(999u64)));
        for _ in 0..100 {
            let v = ch.draw_felt();
            assert!(v.to_u256() < BN254_PRIME, "draw_felt returned value >= prime");
        }
    }

    #[test]
    fn test_commit_resets_counter() {
        let mut ch = Channel::new(Fp::from_u256(U256::from(1u64)));
        ch.commit(Fp::from_u256(U256::from(10u64)));
        let v1 = ch.draw_felt();

        let mut ch2 = Channel::new(Fp::from_u256(U256::from(1u64)));
        ch2.commit(Fp::from_u256(U256::from(10u64)));
        let v2 = ch2.draw_felt();

        assert_eq!(v1, v2);
    }

    #[test]
    fn test_draw_queries_into() {
        let mut ch = Channel::new(Fp::from_u256(U256::from(42u64)));
        ch.commit(Fp::ZERO);
        let mut output = [0usize; 8];
        let written = ch.draw_queries_into(&mut output, 8, 64);
        assert_eq!(written, 8);

        for &idx in &output[..written] {
            assert!(idx < 64, "Index {} out of range", idx);
        }

        for i in 0..written {
            for j in (i + 1)..written {
                assert_ne!(output[i], output[j], "Duplicate query index");
            }
        }
    }
}
