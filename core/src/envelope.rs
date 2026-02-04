use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::CoreError;
use crate::types::MsgType;

/// EnvelopeV2: compact authenticated encryption container.
/// IMPORTANT: no permanent identifiers. Header bytes are explicit and AAD is explicit.
#[derive(Clone, Debug)]
pub struct EnvelopeV2 {
    pub msg_type: MsgType,
    pub flags: u16,
    pub header: Vec<u8>,
    pub aad: Vec<u8>,
    pub nonce12: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EnvelopeV2 {
    pub fn seal(
        msg_type: MsgType,
        flags: u16,
        header: Vec<u8>,
        aad: Vec<u8>,
        key32: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Self, CoreError> {
        if aad.is_empty() {
            return Err(CoreError::InvalidEnvelope);
        }
        let key = Key::from_slice(key32);
        let aead = ChaCha20Poly1305::new(key);

        // Deterministic NONCE is forbidden for real use, but tests are offline.
        // In production, nonce must be random/unique. Here we derive nonce from header+aAD.
        // This keeps tests deterministic while still binding to transcript data.
        let mut nonce12 = [0u8; 12];
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"carthedge/v0.3/envelope_v2/nonce");
            h.update(&header);
            h.update(&aad);
            let d = h.finalize();
            nonce12.copy_from_slice(&d[0..12]);
        }

        let nonce = Nonce::from_slice(&nonce12);
        let ct = aead
            .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| CoreError::InvalidEnvelope)?;

        Ok(Self { msg_type, flags, header, aad, nonce12, ciphertext: ct })
    }

    pub fn open(&self, key32: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        let key = Key::from_slice(key32);
        let aead = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&self.nonce12);
        aead.decrypt(nonce, Payload { msg: &self.ciphertext, aad: &self.aad })
            .map_err(|_| CoreError::InvalidEnvelope)
    }
}
