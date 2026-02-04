use std::collections::BTreeMap;

use crate::error::CoreError;

/// SkippedKeyStore stores message keys for out-of-order delivery.
/// Scope: one epoch at a time (epoch mismatch is rejected by caller).
#[derive(Clone, Debug)]
pub struct SkippedKeyStore {
    cap: usize,
    map: BTreeMap<u64, [u8; 32]>,
}

impl SkippedKeyStore {
    pub fn new(cap: usize) -> Self {
        Self { cap, map: BTreeMap::new() }
    }

    /// Put a skipped message key for `counter`.
    /// Enforces capacity deterministically (evict oldest).
    pub fn put(&mut self, counter: u64, mk: [u8; 32]) -> Result<(), CoreError> {
        self.map.insert(counter, mk);
        while self.map.len() > self.cap {
            // evict smallest counter (oldest)
            let k = *self.map.keys().next().unwrap();
            self.map.remove(&k);
        }
        Ok(())
    }

    /// Take (consume) skipped key for `counter`.
    pub fn take(&mut self, counter: u64) -> Option<[u8; 32]> {
        self.map.remove(&counter)
    }

    /// For tests / introspection
    pub fn len(&self) -> usize {
        self.map.len()
    }
}
