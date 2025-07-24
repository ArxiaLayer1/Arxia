//! Storage backends for Arxia.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use arxia_core::ArxiaError;
use std::collections::HashMap;

/// Trait for key-value storage backends.
pub trait StorageBackend {
    /// Store a value under the given key.
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError>;
    /// Retrieve a value by key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError>;
    /// Delete a key-value pair.
    fn delete(&mut self, key: &[u8]) -> Result<(), ArxiaError>;
    /// Check if a key exists.
    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError>;
}

/// In-memory storage backend for testing.
pub struct MemoryStorage {
    data: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryStorage {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        Ok(self.data.get(key).cloned())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), ArxiaError> {
        self.data.remove(key);
        Ok(())
    }
    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        Ok(self.data.contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage_put_get() {
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        let result = store.get(b"key1").unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_memory_storage_get_missing() {
        let store = MemoryStorage::new();
        let result = store.get(b"missing").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_memory_storage_delete() {
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        store.delete(b"key1").unwrap();
        assert_eq!(store.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_memory_storage_contains() {
        let mut store = MemoryStorage::new();
        store.put(b"key1", b"value1").unwrap();
        assert!(store.contains(b"key1").unwrap());
        assert!(!store.contains(b"key2").unwrap());
    }
}
