//! The `~/.ssh/config` equivalent, stored in localStorage.
//!
//! A host is a name, an optional login user, and a pigeons target. Targets are
//! either `iroh:<endpoint-id>` for a roost or `tcp:host:port` for a plain TCP
//! endpoint, which is what the development server uses.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::platform;

const STORAGE_KEY: &str = "pigeons.web.config.v1";

/// One connectable host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub user: String,
    pub target: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub hosts: Vec<Host>,
    /// Trusted host keys, by host name. Fingerprints only: no key material.
    #[serde(default)]
    pub known_hosts: BTreeMap<String, String>,
}

impl Config {
    pub fn load() -> Self {
        let Some(storage) = platform::storage() else {
            return Self::default();
        };
        let Ok(Some(raw)) = storage.get_item(STORAGE_KEY) else {
            return Self::default();
        };
        let mut config: Self = serde_json::from_str(&raw).unwrap_or_default();
        // Earlier builds pre-filled the target with a bare scheme prefix, which
        // reads as a configured host but is not one. Show it as empty instead.
        for host in &mut config.hosts {
            let target = host.target.trim();
            if target == "iroh:" || target == "tcp:" {
                host.target.clear();
            }
        }
        config
    }

    pub fn save(&self) {
        let Some(storage) = platform::storage() else {
            return;
        };
        if let Ok(raw) = serde_json::to_string(self) {
            let _ = storage.set_item(STORAGE_KEY, &raw);
        }
    }

    pub fn host(&self, name: &str) -> Option<&Host> {
        self.hosts.iter().find(|host| host.name == name)
    }

    /// Adds a host, replacing one with the same name.
    pub fn upsert(&mut self, host: Host) {
        match self
            .hosts
            .iter_mut()
            .find(|existing| existing.name == host.name)
        {
            Some(existing) => *existing = host,
            None => self.hosts.push(host),
        }
        self.hosts.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn remove(&mut self, name: &str) {
        self.hosts.retain(|host| host.name != name);
        self.known_hosts.remove(name);
    }
}
