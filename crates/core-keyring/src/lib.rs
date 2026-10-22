//! Desktop secure storage: macOS Keychain, Windows Credential Manager, Linux Secret Service.
//! If the OS store is unavailable the error is reported; secrets are never silently written to disk.

use core_store::{SecretStore, StoreError};

pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    pub fn new(service: &str) -> Self {
        Self { service: service.to_string() }
    }
    fn entry(&self, id: &str) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(&self.service, id).map_err(|e| StoreError::Secrets(e.to_string()))
    }
    /// Quick check used at start-up to tell the user whether secure storage works.
    pub fn probe(&self) -> Result<(), StoreError> {
        let id = "__probe__";
        self.put(id, "1")?;
        let ok = self.get(id)?.as_deref() == Some("1");
        self.delete(id)?;
        if ok { Ok(()) } else { Err(StoreError::Secrets("read-back mismatch".into())) }
    }
}

impl SecretStore for KeyringStore {
    fn put(&self, id: &str, value: &str) -> Result<(), StoreError> {
        self.entry(id)?.set_password(value).map_err(|e| StoreError::Secrets(e.to_string()))
    }
    fn get(&self, id: &str) -> Result<Option<String>, StoreError> {
        match self.entry(id)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Secrets(e.to_string())),
        }
    }
    fn delete(&self, id: &str) -> Result<(), StoreError> {
        match self.entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Secrets(e.to_string())),
        }
    }
}
