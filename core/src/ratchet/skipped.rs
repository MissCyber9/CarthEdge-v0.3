use std::collections::BTreeMap;
use crate::error::CoreError;

#[derive(Clone, Debug)]
pub struct SkippedKeyStore {
    max: usize,
    map: BTreeMap<u64, [u8; 32]>,
}

impl SkippedKeyStore {
    pub fn new(max: usize) -> Self {
        Self { max, map: BTreeMap::new() }
    }

    pub fn insert(&mut self, counter: u64, key: [u8; 32]) -> Result<(), CoreError> {
        if self.map.len() >= self.max {
            return Err(CoreError::InvalidEnvelope);
        }
        self.map.insert(counter, key);
        Ok(())
    }

    pub fn take(&mut self, counter: u64) -> Option<[u8; 32]> {
        self.map.remove(&counter)
    }
}
