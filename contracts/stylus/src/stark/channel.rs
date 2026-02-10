//! Fiat-Shamir Channel using Poseidon Hash
//!
//! Implements a deterministic transcript for non-interactive proofs.
//! All randomness is derived from Poseidon hashing of the protocol transcript.

use alloy_primitives::U256;

use crate::poseidon::field::{BN254Field, BN254_PRIME};
use crate::poseidon::PoseidonHasher;

/// Fiat-Shamir channel for deterministic challenge generation.
///
/// The channel maintains an internal state that is updated by committing
/// values from the proof. Challenges are derived deterministically from
/// this state using Poseidon hash.
pub struct Channel {
    /// Current channel state
    state: U256,
    /// Counter for unique challenge derivation
    counter: u64,
}

impl Channel {
    /// Create a new channel with an initial seed.
    ///
    /// # Arguments
    /// * `seed` - Initial seed value (typically hash of public inputs)
    pub fn new(seed: U256) -> Self {
        Channel {
            state: seed,
            counter: 0,
        }
    }

    /// Commit a value to the channel transcript.
    ///
    /// Updates the internal state: state = poseidon(state, value)
    ///
    /// # Arguments
    /// * `value` - The value to commit (e.g., Merkle root, polynomial evaluation)
    pub fn commit(&mut self, value: U256) {
        self.state = PoseidonHasher::hash_two(self.state, value);
        self.counter = 0; // Reset counter after each commitment
    }

    /// Draw a random field element from the channel.
    ///
    /// Returns poseidon(state, counter) and increments counter.
    /// This ensures each call returns a different value.
    pub fn draw_felt(&mut self) -> U256 {
        let challenge = PoseidonHasher::hash_two(self.state, U256::from(self.counter));
        self.counter += 1;
        // Ensure result is in field
        if challenge >= BN254_PRIME {
            BN254Field::reduce(challenge)
        } else {
            challenge
        }
    }

    /// Draw multiple random query indices from the channel.
    ///
    /// Generates `count` unique indices in range [0, domain_size).
    /// Uses rejection sampling to avoid bias.
    ///
    /// # Arguments
    /// * `count` - Number of query indices to generate
    /// * `domain_size` - Size of the evaluation domain (must be power of 2)
    ///
    /// # Returns
    /// Vector of unique query indices
    #[cfg(test)]
    pub fn draw_queries(&mut self, count: usize, domain_size: usize) -> alloc::vec::Vec<usize> {
        let mut indices = alloc::vec::Vec::with_capacity(count);

        while indices.len() < count {
            let raw = self.draw_felt();
            // For power-of-2 domains, use bit masking
            let mask = U256::from((domain_size - 1) as u64);
            let index = (raw & mask).as_limbs()[0] as usize;

            // Ensure uniqueness
            if !indices.contains(&index) {
                indices.push(index);
            }
        }

        indices
    }

    /// Draw query indices without Vec allocation (no_std compatible).
    /// Writes into a provided slice. Returns number of indices written.
    ///
    /// # Arguments
    /// * `output` - Mutable slice to write indices into
    /// * `count` - Number of indices to generate
    /// * `domain_size` - Size of the domain
    pub fn draw_queries_into(&mut self, output: &mut [usize], count: usize, domain_size: usize) -> usize {
        let count = core::cmp::min(count, output.len());
        let mut written = 0;

        while written < count {
            let raw = self.draw_felt();
            let mask = U256::from((domain_size - 1) as u64);
            let index = (raw & mask).as_limbs()[0] as usize;

            // Check uniqueness
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

    /// Get current state (useful for debugging/testing)
    pub fn state(&self) -> U256 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_deterministic() {
        let seed = U256::from(42u64);

        let mut ch1 = Channel::new(seed);
        ch1.commit(U256::from(100u64));
        let v1 = ch1.draw_felt();

        let mut ch2 = Channel::new(seed);
        ch2.commit(U256::from(100u64));
        let v2 = ch2.draw_felt();

        assert_eq!(v1, v2, "Channel not deterministic");
    }

    #[test]
    fn test_channel_different_commits_different_output() {
        let seed = U256::from(42u64);

        let mut ch1 = Channel::new(seed);
        ch1.commit(U256::from(100u64));
        let v1 = ch1.draw_felt();

        let mut ch2 = Channel::new(seed);
        ch2.commit(U256::from(200u64));
        let v2 = ch2.draw_felt();

        assert_ne!(v1, v2, "Different commits should produce different output");
    }

    #[test]
    fn test_draw_felt_unique() {
        let mut ch = Channel::new(U256::from(1u64));
        ch.commit(U256::from(0u64));

        let v1 = ch.draw_felt();
        let v2 = ch.draw_felt();
        let v3 = ch.draw_felt();

        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_draw_felt_in_field() {
        let mut ch = Channel::new(U256::from(999u64));
        for _ in 0..100 {
            let v = ch.draw_felt();
            assert!(v < BN254_PRIME, "draw_felt returned value >= prime");
        }
    }

    #[test]
    fn test_commit_resets_counter() {
        let mut ch = Channel::new(U256::from(1u64));
        ch.commit(U256::from(10u64));
        let v1 = ch.draw_felt();

        // Recommit same value should give same first draw
        let mut ch2 = Channel::new(U256::from(1u64));
        ch2.commit(U256::from(10u64));
        let v2 = ch2.draw_felt();

        assert_eq!(v1, v2);
    }

    #[test]
    fn test_draw_queries_into() {
        let mut ch = Channel::new(U256::from(42u64));
        ch.commit(U256::from(0u64));
        let mut output = [0usize; 8];
        let written = ch.draw_queries_into(&mut output, 8, 64);
        assert_eq!(written, 8);

        // All should be in range [0, 64)
        for &idx in &output[..written] {
            assert!(idx < 64, "Index {} out of range", idx);
        }

        // All should be unique
        for i in 0..written {
            for j in (i + 1)..written {
                assert_ne!(output[i], output[j], "Duplicate query index");
            }
        }
    }
}
