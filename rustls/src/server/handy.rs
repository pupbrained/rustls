use crate::limited_cache;
use crate::server;

use alloc::sync::Arc;
use std::sync::Mutex;

/// Something which never stores sessions.
pub struct NoServerSessionStorage {}

impl server::StoresServerSessions for NoServerSessionStorage {
    fn put(&self, _id: Vec<u8>, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn can_cache(&self) -> bool {
        false
    }
}

/// An implementer of `StoresServerSessions` that stores everything
/// in memory.  If enforces a limit on the number of stored sessions
/// to bound memory usage.
pub struct ServerSessionMemoryCache {
    cache: Mutex<limited_cache::LimitedCache<Vec<u8>, Vec<u8>>>,
}

impl ServerSessionMemoryCache {
    /// Make a new ServerSessionMemoryCache.  `size` is the maximum
    /// number of stored sessions, and may be rounded-up for
    /// efficiency.
    pub fn new(size: usize) -> Arc<Self> {
        Arc::new(Self {
            cache: Mutex::new(limited_cache::LimitedCache::new(size)),
        })
    }
}

impl server::StoresServerSessions for ServerSessionMemoryCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache
            .lock()
            .unwrap()
            .insert(key, value);
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock().unwrap().remove(key)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

/// Something which never produces tickets.
pub(super) struct NeverProducesTickets {}

impl server::ProducesTickets for NeverProducesTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::ProducesTickets;
    use crate::server::StoresServerSessions;

    #[test]
    fn test_noserversessionstorage_drops_put() {
        let c = NoServerSessionStorage {};
        assert!(!c.put(vec![0x01], vec![0x02]));
    }

    #[test]
    fn test_noserversessionstorage_denies_gets() {
        let c = NoServerSessionStorage {};
        c.put(vec![0x01], vec![0x02]);
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.get(&[0x01]), None);
        assert_eq!(c.get(&[0x02]), None);
    }

    #[test]
    fn test_noserversessionstorage_denies_takes() {
        let c = NoServerSessionStorage {};
        assert_eq!(c.take(&[]), None);
        assert_eq!(c.take(&[0x01]), None);
        assert_eq!(c.take(&[0x02]), None);
    }

    #[test]
    fn test_serversessionmemorycache_accepts_put() {
        let c = ServerSessionMemoryCache::new(4);
        assert!(c.put(vec![0x01], vec![0x02]));
    }

    #[test]
    fn test_serversessionmemorycache_persists_put() {
        let c = ServerSessionMemoryCache::new(4);
        assert!(c.put(vec![0x01], vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
    }

    #[test]
    fn test_serversessionmemorycache_overwrites_put() {
        let c = ServerSessionMemoryCache::new(4);
        assert!(c.put(vec![0x01], vec![0x02]));
        assert!(c.put(vec![0x01], vec![0x04]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
    }

    #[test]
    fn test_serversessionmemorycache_drops_to_maintain_size_invariant() {
        let c = ServerSessionMemoryCache::new(2);
        assert!(c.put(vec![0x01], vec![0x02]));
        assert!(c.put(vec![0x03], vec![0x04]));
        assert!(c.put(vec![0x05], vec![0x06]));
        assert!(c.put(vec![0x07], vec![0x08]));
        assert!(c.put(vec![0x09], vec![0x0a]));

        let count = c.get(&[0x01]).iter().count()
            + c.get(&[0x03]).iter().count()
            + c.get(&[0x05]).iter().count()
            + c.get(&[0x07]).iter().count()
            + c.get(&[0x09]).iter().count();

        assert!(count < 5);
    }

    #[test]
    fn test_neverproducestickets_does_nothing() {
        let npt = NeverProducesTickets {};
        assert!(!npt.enabled());
        assert_eq!(0, npt.lifetime());
        assert_eq!(None, npt.encrypt(&[]));
        assert_eq!(None, npt.decrypt(&[]));
    }
}
