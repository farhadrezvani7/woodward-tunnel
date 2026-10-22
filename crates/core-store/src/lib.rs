//! Profile storage. Metadata lives in SQLite; secrets (keys, passwords, UUIDs, inline certs)
//! go to a [`SecretStore`] backed by the OS secure storage and never touch the database.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use core_model::{Profile, Protocol, Secret};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(String),
    #[error("secure storage unavailable: {0}")]
    Secrets(String),
    #[error("profile not found")]
    NotFound,
    #[error("stored data is damaged")]
    Corrupt,
}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

/// Where secrets live. Desktop: OS keychain. Mobile: Keystore/Keychain through a callback.
pub trait SecretStore: Send + Sync {
    fn put(&self, id: &str, value: &str) -> Result<(), StoreError>;
    fn get(&self, id: &str) -> Result<Option<String>, StoreError>;
    fn delete(&self, id: &str) -> Result<(), StoreError>;
}

/// In-memory store for tests and for explicit "do not remember" sessions.
#[derive(Default)]
pub struct MemorySecretStore(Mutex<HashMap<String, String>>);
impl SecretStore for MemorySecretStore {
    fn put(&self, id: &str, value: &str) -> Result<(), StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Corrupt)?
            .insert(id.into(), value.into());
        Ok(())
    }
    fn get(&self, id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StoreError::Corrupt)?
            .get(id)
            .cloned())
    }
    fn delete(&self, id: &str) -> Result<(), StoreError> {
        self.0.lock().map_err(|_| StoreError::Corrupt)?.remove(id);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub group: String,
    pub created_at: i64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct AddReport {
    pub added: Vec<ProfileSummary>,
    /// Profiles that already existed (same protocol, server and credentials).
    pub duplicates: usize,
}

pub struct Store {
    db: Mutex<Connection>,
    secrets: Arc<dyn SecretStore>,
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    // Randomness failure is not recoverable for id generation; fall back to a time-derived id.
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b = t.to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fingerprint(p: &Profile) -> String {
    let mut h = Sha256::new();
    h.update(p.protocol.id());
    h.update(p.host.as_bytes());
    h.update(p.port.to_be_bytes());
    for (k, v) in &p.secrets {
        h.update(k.as_bytes());
        h.update(v.expose().as_bytes());
    }
    for (k, v) in &p.settings {
        h.update(k.as_bytes());
        h.update(v.as_bytes());
    }
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS profiles(
  id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, name TEXT NOT NULL, protocol TEXT NOT NULL,
  host TEXT NOT NULL, port INTEGER NOT NULL, group_name TEXT NOT NULL DEFAULT '',
  settings TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS profiles_group ON profiles(group_name);
PRAGMA user_version = 1;";

impl Store {
    pub fn open(path: &Path, secrets: Arc<dyn SecretStore>) -> Result<Self, StoreError> {
        let db = Connection::open(path)?;
        Self::init(db, secrets)
    }
    pub fn open_in_memory(secrets: Arc<dyn SecretStore>) -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, secrets)
    }
    fn init(db: Connection, secrets: Arc<dyn SecretStore>) -> Result<Self, StoreError> {
        db.execute_batch(SCHEMA)?;
        Ok(Self {
            db: Mutex::new(db),
            secrets,
        })
    }
    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.db.lock().map_err(|_| StoreError::Corrupt)
    }

    pub fn add_many(&self, profiles: Vec<Profile>, group: &str) -> Result<AddReport, StoreError> {
        let mut report = AddReport::default();
        for p in profiles {
            let fp = fingerprint(&p);
            let id = new_id();
            let db = self.conn()?;
            let exists: Option<String> = db
                .query_row("SELECT id FROM profiles WHERE fingerprint=?1", [&fp], |r| {
                    r.get(0)
                })
                .optional()?;
            if exists.is_some() {
                report.duplicates += 1;
                continue;
            }
            // Secrets first: a crash leaves an orphan secret, never a profile without its key.
            let secret_json = serde_json::to_string(
                &p.secrets
                    .iter()
                    .map(|(k, v)| (k.clone(), v.expose().to_string()))
                    .collect::<BTreeMap<_, _>>(),
            )
            .map_err(|_| StoreError::Corrupt)?;
            if !p.secrets.is_empty() {
                self.secrets.put(&id, &secret_json)?;
            }
            let settings = serde_json::to_string(&p.settings).map_err(|_| StoreError::Corrupt)?;
            let created = now();
            let res = db.execute(
                "INSERT INTO profiles(id,fingerprint,name,protocol,host,port,group_name,settings,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![id, fp, p.name, p.protocol.id(), p.host, p.port, group, settings, created],
            );
            if let Err(e) = res {
                let _ = self.secrets.delete(&id);
                return Err(e.into());
            }
            report.added.push(ProfileSummary {
                id,
                name: p.name,
                protocol: p.protocol,
                host: p.host,
                port: p.port,
                group: group.into(),
                created_at: created,
            });
        }
        Ok(report)
    }

    pub fn list(&self) -> Result<Vec<ProfileSummary>, StoreError> {
        let db = self.conn()?;
        let mut st = db.prepare("SELECT id,name,protocol,host,port,group_name,created_at FROM profiles ORDER BY group_name, created_at, name")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, u16>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, proto, host, port, group, created_at) = row?;
            let protocol = Protocol::from_id(&proto).ok_or(StoreError::Corrupt)?;
            out.push(ProfileSummary {
                id,
                name,
                protocol,
                host,
                port,
                group,
                created_at,
            });
        }
        Ok(out)
    }

    /// Full profile including secrets (for connecting).
    pub fn get(&self, id: &str) -> Result<Profile, StoreError> {
        let db = self.conn()?;
        let row = db
            .query_row(
                "SELECT name,protocol,host,port,settings FROM profiles WHERE id=?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, u16>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let (name, proto, host, port, settings) = row;
        let protocol = Protocol::from_id(&proto).ok_or(StoreError::Corrupt)?;
        let settings: BTreeMap<String, String> =
            serde_json::from_str(&settings).map_err(|_| StoreError::Corrupt)?;
        let secrets: BTreeMap<String, Secret> = match self.secrets.get(id)? {
            Some(j) => serde_json::from_str::<BTreeMap<String, String>>(&j)
                .map_err(|_| StoreError::Corrupt)?
                .into_iter()
                .map(|(k, v)| (k, Secret::new(v)))
                .collect(),
            None => BTreeMap::new(),
        };
        Ok(Profile {
            name,
            protocol,
            host,
            port,
            settings,
            secrets,
        })
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<(), StoreError> {
        let name: String = name.chars().filter(|c| !c.is_control()).take(100).collect();
        let n = self.conn()?.execute(
            "UPDATE profiles SET name=?1 WHERE id=?2",
            params![name.trim(), id],
        )?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    pub fn set_group(&self, id: &str, group: &str) -> Result<(), StoreError> {
        let group: String = group.chars().filter(|c| !c.is_control()).take(60).collect();
        let n = self.conn()?.execute(
            "UPDATE profiles SET group_name=?1 WHERE id=?2",
            params![group.trim(), id],
        )?;
        if n == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        let n = self
            .conn()?
            .execute("DELETE FROM profiles WHERE id=?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        self.secrets.delete(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, pw: &str) -> Profile {
        let mut secrets = BTreeMap::new();
        secrets.insert("password".into(), Secret::new(pw));
        let mut settings = BTreeMap::new();
        settings.insert("sni".into(), "a.example.com".into());
        Profile {
            name: name.into(),
            protocol: Protocol::Trojan,
            host: "a.example.com".into(),
            port: 443,
            settings,
            secrets,
        }
    }

    fn store() -> (Store, Arc<MemorySecretStore>) {
        let m = Arc::new(MemorySecretStore::default());
        (Store::open_in_memory(m.clone()).unwrap(), m)
    }

    #[test]
    fn add_list_get_round_trip_keeps_secrets_out_of_db() {
        let (s, m) = store();
        let r = s.add_many(vec![profile("A", "hunter22")], "Work").unwrap();
        assert_eq!(r.added.len(), 1);
        let id = &r.added[0].id;
        let p = s.get(id).unwrap();
        assert_eq!(p.secrets["password"].expose(), "hunter22");
        assert_eq!(s.list().unwrap()[0].group, "Work");
        // The database file text must not contain the secret.
        let dump: String = s
            .conn()
            .unwrap()
            .query_row(
                "SELECT group_concat(settings||name||host) FROM profiles",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!dump.contains("hunter22"));
        assert!(m.get(id).unwrap().unwrap().contains("hunter22"));
    }

    #[test]
    fn duplicates_are_skipped() {
        let (s, _) = store();
        s.add_many(vec![profile("A", "pw123456")], "").unwrap();
        let r = s
            .add_many(
                vec![profile("B", "pw123456"), profile("C", "other-pass")],
                "",
            )
            .unwrap();
        assert_eq!((r.added.len(), r.duplicates), (1, 1));
    }

    #[test]
    fn rename_group_delete() {
        let (s, m) = store();
        let id = s
            .add_many(vec![profile("A", "pw123456")], "")
            .unwrap()
            .added[0]
            .id
            .clone();
        s.rename(&id, "  New\nName ").unwrap();
        s.set_group(&id, "Home").unwrap();
        let l = s.list().unwrap();
        assert_eq!(
            (l[0].name.as_str(), l[0].group.as_str()),
            ("NewName", "Home")
        );
        s.delete(&id).unwrap();
        assert!(s.list().unwrap().is_empty());
        assert!(m.get(&id).unwrap().is_none());
        assert!(matches!(s.get(&id), Err(StoreError::NotFound)));
        assert!(matches!(s.delete(&id), Err(StoreError::NotFound)));
    }

    #[test]
    fn secret_store_failure_means_no_profile_row() {
        struct Failing;
        impl SecretStore for Failing {
            fn put(&self, _: &str, _: &str) -> Result<(), StoreError> {
                Err(StoreError::Secrets("locked".into()))
            }
            fn get(&self, _: &str) -> Result<Option<String>, StoreError> {
                Ok(None)
            }
            fn delete(&self, _: &str) -> Result<(), StoreError> {
                Ok(())
            }
        }
        let s = Store::open_in_memory(Arc::new(Failing)).unwrap();
        assert!(s.add_many(vec![profile("A", "pw123456")], "").is_err());
        assert!(s.list().unwrap().is_empty());
    }

    #[test]
    fn persists_on_disk() {
        let dir = std::env::temp_dir().join(format!("wt-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.db");
        let m = Arc::new(MemorySecretStore::default());
        {
            let s = Store::open(&path, m.clone()).unwrap();
            s.add_many(vec![profile("A", "pw123456")], "").unwrap();
        }
        let s = Store::open(&path, m).unwrap();
        assert_eq!(s.list().unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
