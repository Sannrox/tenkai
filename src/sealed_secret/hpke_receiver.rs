//! The HPKE receiver for a sealing key whose private half stays in a token
//! (RFC 9180, base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//! AES-256-GCM): the suite [`super::seal`] uses.
//!
//! A file key opens wraps through the `hpke` crate, which needs the private
//! scalar. A token never releases it, but it can compute the one value that
//! needs it: the ECDH shared point with the sender's ephemeral key. Every
//! other step is public math, done here. [`open`] takes that ECDH as a
//! function, so it is checked against the `hpke` crate with a software key
//! (see the tests) and runs unchanged against a token.

use anyhow::{Result, bail};
use hkdf::Hkdf;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// DHKEM(P-256, HKDF-SHA256).
const KEM_ID: u16 = 0x0010;
/// HKDF-SHA256.
const KDF_ID: u16 = 0x0001;
/// AES-256-GCM.
const AEAD_ID: u16 = 0x0002;
/// Uncompressed P-256 point.
const POINT_BYTES: usize = 65;
const HASH_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

fn kem_suite() -> Vec<u8> {
    [b"KEM".as_slice(), &KEM_ID.to_be_bytes()].concat()
}

fn hpke_suite() -> Vec<u8> {
    [
        b"HPKE".as_slice(),
        &KEM_ID.to_be_bytes(),
        &KDF_ID.to_be_bytes(),
        &AEAD_ID.to_be_bytes(),
    ]
    .concat()
}

/// RFC 9180 `LabeledExtract`: the PRK, which keys the next step.
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Hkdf<Sha256> {
    let labeled = Zeroizing::new([b"HPKE-v1".as_slice(), suite, label, ikm].concat());
    let (_, hkdf) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    hkdf
}

/// RFC 9180 `LabeledExtract`, as bytes: a PRK that is input to another
/// extract rather than a key.
fn labeled_extract_bytes(
    suite: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Zeroizing<Vec<u8>> {
    let labeled = Zeroizing::new([b"HPKE-v1".as_slice(), suite, label, ikm].concat());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    Zeroizing::new(prk.to_vec())
}

/// RFC 9180 `LabeledExpand`.
fn labeled_expand(
    suite: &[u8],
    prk: &Hkdf<Sha256>,
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let length_prefix = u16::try_from(length)?.to_be_bytes();
    let labeled_info = [length_prefix.as_slice(), b"HPKE-v1", suite, label, info].concat();
    let mut out = Zeroizing::new(vec![0; length]);
    prk.expand(&labeled_info, &mut out)
        .map_err(|_| anyhow::anyhow!("HPKE expand length"))?;
    Ok(out)
}

/// Open one HPKE single-shot wrap sealed to `recipient` (an uncompressed
/// P-256 point). `ecdh` returns the x coordinate of the shared point with
/// `encapsulated`, the sender's ephemeral public key: the only step that
/// needs the private key. Errors never carry key material.
pub(super) fn open(
    recipient: &[u8],
    encapsulated: &[u8],
    info: &[u8],
    aad: &[u8],
    wrapped: &[u8],
    ecdh: impl FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if encapsulated.len() != POINT_BYTES || encapsulated[0] != 0x04 {
        bail!("the encapsulated key is not an uncompressed P-256 point");
    }
    let dh = ecdh(encapsulated)?;
    if dh.len() != HASH_BYTES {
        bail!("the shared secret has the wrong length");
    }

    // DHKEM Decap: ExtractAndExpand(dh, enc || pkRm).
    let kem = kem_suite();
    let kem_context = [encapsulated, recipient].concat();
    let eae_prk = labeled_extract(&kem, b"", b"eae_prk", &dh);
    let shared_secret = labeled_expand(&kem, &eae_prk, b"shared_secret", &kem_context, HASH_BYTES)?;

    // KeySchedule, base mode: no PSK.
    let hpke = hpke_suite();
    let psk_id_hash = labeled_extract_bytes(&hpke, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract_bytes(&hpke, b"", b"info_hash", info);
    let context = [&[0x00][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&hpke, &shared_secret, b"secret", b"");
    let key = labeled_expand(&hpke, &secret, b"key", &context, KEY_BYTES)?;
    let base_nonce = labeled_expand(&hpke, &secret, b"base_nonce", &context, NONCE_BYTES)?;

    // Single shot: sequence number 0, so the nonce is the base nonce.
    let refused = || anyhow::anyhow!("the wrap does not open for this key");
    let nonce = Nonce::try_assume_unique_for_key(&base_nonce).map_err(|_| refused())?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).map_err(|_| refused())?);
    let mut body = Zeroizing::new(wrapped.to_vec());
    let plain = key
        .open_in_place(nonce, Aad::from(aad), &mut body)
        .map_err(|_| refused())?;
    Ok(Zeroizing::new(plain.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Kem as _, Serializable as _};

    type Kem = hpke::kem::DhP256HkdfSha256;
    type Kdf = hpke::kdf::HkdfSha256;
    type Aead = hpke::aead::AesGcm256;

    /// A software ECDH over `scalar`: what a token computes.
    fn software_ecdh(scalar: &p256::SecretKey) -> impl FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let scalar = scalar.clone();
        move |peer| {
            let peer = p256::PublicKey::from_sec1_bytes(peer)
                .map_err(|_| anyhow::anyhow!("not a P-256 point"))?;
            let shared = p256::ecdh::diffie_hellman(scalar.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }
    }

    #[test]
    fn opening_matches_the_hpke_crate_on_the_same_key() {
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        for seed in 0..8_u64 {
            let (private, public) = Kem::gen_keypair(&mut rng);
            let recipient = public.to_bytes().to_vec();
            let message = format!("data key {seed}").into_bytes();
            let (encapsulated, wrapped) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
                &hpke::OpModeS::Base,
                &public,
                b"tenkai.sealed-secret.v1",
                &message,
                b"associated data",
                &mut rng,
            )
            .unwrap();
            let scalar = p256::SecretKey::from_slice(&private.to_bytes()).unwrap();

            let opened = open(
                &recipient,
                &encapsulated.to_bytes(),
                b"tenkai.sealed-secret.v1",
                b"associated data",
                &wrapped,
                software_ecdh(&scalar),
            )
            .unwrap();
            assert_eq!(opened.as_slice(), message.as_slice(), "seed {seed}");

            // Another target's associated data, or another info, is refused.
            for (info, aad) in [
                (
                    b"tenkai.sealed-secret.v1".as_slice(),
                    b"other target".as_slice(),
                ),
                (b"other info".as_slice(), b"associated data".as_slice()),
            ] {
                let error = open(
                    &recipient,
                    &encapsulated.to_bytes(),
                    info,
                    aad,
                    &wrapped,
                    software_ecdh(&scalar),
                )
                .unwrap_err();
                assert!(
                    !format!("{error:#}").contains(&format!("{seed}")),
                    "{error:#}"
                );
            }
        }
    }
}
