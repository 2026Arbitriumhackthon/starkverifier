//! Fiat-Shamir Channel (prover side)
//!
//! Must produce identical output to the on-chain verifier's channel
//! given the same inputs. Both use Poseidon hash.

use alloy_primitives::U256;
use crate::field::{BN254Field, BN254_PRIME};
use crate::poseidon::PoseidonHasher;

/// Fiat-Shamir channel for deterministic challenge generation.
pub struct Channel {
    state: U256,
    counter: u64,
}

impl Channel {
    pub fn new(seed: U256) -> Self {
        Channel {
            state: seed,
            counter: 0,
        }
    }

    pub fn commit(&mut self, value: U256) {
        self.state = PoseidonHasher::hash_two(self.state, value);
        self.counter = 0;
    }

    pub fn draw_felt(&mut self) -> U256 {
        let challenge = PoseidonHasher::hash_two(self.state, U256::from(self.counter));
        self.counter += 1;
        if challenge >= BN254_PRIME {
            BN254Field::reduce(challenge)
        } else {
            challenge
        }
    }

    pub fn draw_queries(&mut self, count: usize, domain_size: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(count);

        while indices.len() < count {
            let raw = self.draw_felt();
            let mask = U256::from((domain_size - 1) as u64);
            let index = (raw & mask).as_limbs()[0] as usize;

            if !indices.contains(&index) {
                indices.push(index);
            }
        }

        indices
    }

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

        assert_eq!(v1, v2);
    }
}
