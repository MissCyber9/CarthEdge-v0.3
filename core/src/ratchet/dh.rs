use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct DhKeyPair {
    secret: Option<EphemeralSecret>,
    pub public: PublicKey,
}

impl DhKeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret: Some(secret), public }
    }

    /// Compute DH once. Consumes the internal secret (ephemeral by design).
    pub fn dh_once(&mut self, peer_pub: &PublicKey) -> [u8; 32] {
        let secret = self.secret.take().expect("dh_once called twice without regenerate()");
        secret.diffie_hellman(peer_pub).to_bytes()
    }

    /// Regenerate local ephemeral DH keypair after a DH step.
    pub fn regenerate(&mut self) {
        *self = Self::generate();
    }
}
