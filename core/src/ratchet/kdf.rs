use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-Extract + HKDF-Expand for fixed sizes.
///
/// We keep these small and explicit so tests can validate behavior.
pub fn hkdf_extract_and_expand_96(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 96] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 96];
    hk.expand(info, &mut okm).expect("hkdf expand 96");
    okm
}

pub fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    // Treat `prk` as ikm with empty salt for a compact "expand-only" usage.
    let hk = Hkdf::<Sha256>::new(None, prk);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf expand 32");
    okm
}
