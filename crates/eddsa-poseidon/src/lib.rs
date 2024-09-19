pub mod ed_on_bn254_twist;
pub mod eddsa;
pub mod signature;

use ark_ff::PrimeField;
use digest::Digest;
pub use eddsa::*;

pub(crate) fn from_digest<F: PrimeField, D: Digest>(digest: D) -> F {
    let bytes = digest.finalize();
    F::from_le_bytes_mod_order(&bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Verify,
    BadDigestOutput,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Error::Verify => write!(f, "Signature verification failed"),
            Error::BadDigestOutput => write!(f, "Bad digest output size"),
        }
    }
}

impl ark_std::error::Error for Error {}

#[cfg(test)]
mod test {

    use crate::SigningKey;
    use ark_bn254::Fr;
    use ark_crypto_primitives::sponge::poseidon::{
        find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    };
    use ark_crypto_primitives::sponge::{
        Absorb, CryptographicSponge, FieldBasedCryptographicSponge, FieldElementSize,
    };
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ec::CurveConfig;
    use ark_ed_on_bn254::Fq;
    use ark_ff::Field;
    use ark_ff::PrimeField;
    use ark_ff::{BigInteger, BigInteger256};
    use digest::Digest;
    use rand_core::OsRng;
    use std::any::TypeId;
    use std::str::FromStr;

    /// Generates poseidon constants and returns the config
    pub fn poseidon_config<F: PrimeField>(
        rate: usize,
        full_rounds: usize,
        partial_rounds: usize,
    ) -> PoseidonConfig<F> {
        let (ark, mds) = find_poseidon_ark_and_mds(
            F::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds as u64,
            partial_rounds as u64,
            0,
        );
        PoseidonConfig::new(full_rounds, partial_rounds, 5, mds, ark, rate, 1)
    }

    fn num_bits<F: PrimeField>(a: &FieldElementSize) -> usize {
        if let FieldElementSize::Truncated(num_bits) = a {
            if *num_bits > (F::MODULUS_BIT_SIZE as usize) {
                panic!("num_bits is greater than the capacity of the field.")
            }
        };
        (F::MODULUS_BIT_SIZE - 1) as usize
    }

    pub(crate) fn non_native<F1: PrimeField, F2: PrimeField>(
        sponge: &mut PoseidonSponge<F1>,
        x: F1,
        sizes: &[FieldElementSize],
    ) -> Vec<F2> {
        if sizes.len() == 0 {
            return Vec::new();
        }

        let mut total_bits = 0usize;
        for size in sizes {
            total_bits += num_bits::<F2>(size);
        }

        // let bits = sponge.squeeze_bits(total_bits);
        // let mut bits_window = bits.as_slice();
        let bigint = x.into_bigint();
        let big_bits = bigint.to_bits_le();
        let mut bits_window = big_bits.as_slice();

        let mut output = Vec::with_capacity(sizes.len());
        for size in sizes {
            let num_bits = num_bits::<F2>(size);
            let nonnative_bits_le: Vec<bool> = bits_window[..num_bits + 2].to_vec();
            bits_window = &bits_window[num_bits..];

            let nonnative_bytes = nonnative_bits_le
                .chunks(8)
                .map(|bits| {
                    let mut byte = 0u8;
                    for (i, &bit) in bits.into_iter().enumerate() {
                        if bit {
                            byte += 1 << i;
                        }
                    }
                    byte
                })
                .collect::<Vec<_>>();

            output.push(F2::from_le_bytes_mod_order(nonnative_bytes.as_slice()));
        }

        output
    }

    fn run_test<TE: TECurveConfig + Clone, D: Digest>()
    where
        TE::BaseField: Absorb + PrimeField,
    {
        let poseidon: PoseidonConfig<<TE as CurveConfig>::BaseField> = poseidon_config(5, 8, 60);
        let signing_key = SigningKey::<TE>::generate::<D>(&mut OsRng).unwrap();
        let message = TE::BaseField::ONE;
        let signature = signing_key.sign::<D, TE::BaseField>(&poseidon, &message);
        let public_key = signing_key.public_key();

        println!("poseidon m {:#?}", TE::ScalarField::ONE.to_string());
        println!("poseidon rx {:#?}", signature.r().x.to_string());
        println!("poseidon ry {:#?}", signature.r().y.to_string());
        println!("poseidon s {:#?}", signature.s().to_string());
        println!("poseidon pub 0{:#?}", public_key.xy().0.to_string());
        println!("poseidon pub 1 {:#?}", public_key.xy().1.to_string());

        public_key
            .verify::<TE::BaseField>(&poseidon, &message, &signature)
            .unwrap();
    }

    #[test]
    fn test_eddsa() {
        run_test::<ark_ed_on_bn254::EdwardsConfig, sha2::Sha512>();
        //run_test::<ark_ed_on_bn254::EdwardsConfig, blake2::Blake2b512>();
        run_test::<crate::ed_on_bn254_twist::EdwardsConfig, sha2::Sha512>();
        //run_test::<ark_ed_on_bls12_381::EdwardsConfig, sha2::Sha512>();
        //run_test::<ark_ed_on_bls12_381_bandersnatch::EdwardsConfig, sha2::Sha512>();
    }
}
