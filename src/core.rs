use anyhow::{Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUser {
    pub id: String,
    pub credential: String,
    pub upload_limit_bps: Option<u64>,
    pub download_limit_bps: Option<u64>,
    pub quota_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoreUserLimits {
    pub upload_limit_bps: Option<u64>,
    pub download_limit_bps: Option<u64>,
    pub quota_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrafficSnapshot {
    pub user_id: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub online_sessions: u64,
    pub quota_bytes: Option<u64>,
    pub quota_remaining_bytes: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ProxyCore {
    inner: Arc<CoreInner>,
}

#[derive(Debug, Default)]
struct CoreInner {
    users: RwLock<HashMap<String, Arc<UserState>>>,
    credentials: RwLock<HashMap<String, String>>,
}

#[derive(Debug)]
struct UserState {
    id: String,
    upload: AtomicU64,
    download: AtomicU64,
    online: AtomicU64,
    limits: RwLock<CoreUserLimits>,
    upload_limiter: Mutex<ByteRateLimiter>,
    download_limiter: Mutex<ByteRateLimiter>,
}

#[derive(Debug)]
struct ActiveSession {
    user: Arc<UserState>,
}

#[derive(Clone, Debug)]
pub struct CoreSession {
    inner: Arc<ActiveSession>,
}

#[derive(Debug)]
struct ByteRateLimiter {
    bytes_per_second: Option<u64>,
    next: Instant,
}

impl CoreUser {
    pub fn password(id: impl Into<String>, credential: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            credential: credential.into(),
            upload_limit_bps: None,
            download_limit_bps: None,
            quota_bytes: None,
        }
    }

    fn limits(&self) -> CoreUserLimits {
        CoreUserLimits {
            upload_limit_bps: self.upload_limit_bps,
            download_limit_bps: self.download_limit_bps,
            quota_bytes: self.quota_bytes,
        }
    }
}

impl ProxyCore {
    pub fn new(users: Vec<CoreUser>) -> Result<Self> {
        let core = Self {
            inner: Arc::new(CoreInner::default()),
        };
        core.replace_users(users)?;
        Ok(core)
    }

    pub fn from_credentials(password: &str, users: &[String]) -> Self {
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        let password = password.trim();
        if !password.is_empty() && seen.insert(password.to_string()) {
            entries.push(CoreUser::password("default", password));
        }
        for user in users {
            let credential = user.trim();
            if credential.is_empty() || !seen.insert(credential.to_string()) {
                continue;
            }
            entries.push(CoreUser::password(credential, credential));
        }
        Self::new(entries).expect("deduplicated core credentials must be valid")
    }

    pub fn empty() -> Self {
        Self {
            inner: Arc::new(CoreInner::default()),
        }
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) -> Result<()> {
        let mut ids = HashSet::new();
        let mut credentials = HashSet::new();
        for user in &users {
            ensure!(!user.id.trim().is_empty(), "core user id is empty");
            ensure!(
                !user.credential.trim().is_empty(),
                "core user credential is empty"
            );
            ensure!(
                ids.insert(user.id.clone()),
                "duplicate core user id {}",
                user.id
            );
            ensure!(
                credentials.insert(user.credential.clone()),
                "duplicate core credential for user {}",
                user.id
            );
        }

        let mut user_map = HashMap::new();
        let mut credential_map = HashMap::new();
        for user in users {
            credential_map.insert(user.credential.clone(), user.id.clone());
            user_map.insert(
                user.id.clone(),
                Arc::new(UserState {
                    id: user.id.clone(),
                    upload: AtomicU64::new(0),
                    download: AtomicU64::new(0),
                    online: AtomicU64::new(0),
                    limits: RwLock::new(user.limits()),
                    upload_limiter: Mutex::new(ByteRateLimiter::new(user.upload_limit_bps)),
                    download_limiter: Mutex::new(ByteRateLimiter::new(user.download_limit_bps)),
                }),
            );
        }

        *self.inner.users.write().expect("core users lock poisoned") = user_map;
        *self
            .inner
            .credentials
            .write()
            .expect("core credentials lock poisoned") = credential_map;
        Ok(())
    }

    pub async fn authenticate(&self, credential: &str) -> Result<CoreSession> {
        let credential = credential.trim();
        let user_id = self
            .inner
            .credentials
            .read()
            .expect("core credentials lock poisoned")
            .get(credential)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("core authentication failed"))?;
        self.open_session(&user_id).await
    }

    pub async fn open_session(&self, user_id: &str) -> Result<CoreSession> {
        let user = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .get(user_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("core user not found: {user_id}"))?;
        user.online.fetch_add(1, Ordering::SeqCst);
        Ok(CoreSession {
            inner: Arc::new(ActiveSession { user }),
        })
    }

    pub async fn set_limits(&self, user_id: &str, limits: CoreUserLimits) -> Result<()> {
        let user = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .get(user_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("core user not found: {user_id}"))?;
        *user.limits.write().expect("core limits lock poisoned") = limits;
        user.upload_limiter
            .lock()
            .await
            .set_rate(limits.upload_limit_bps);
        user.download_limiter
            .lock()
            .await
            .set_rate(limits.download_limit_bps);
        Ok(())
    }

    pub async fn snapshot(&self) -> Vec<TrafficSnapshot> {
        let users = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut snapshots = Vec::with_capacity(users.len());
        for user in users {
            snapshots.push(user.snapshot().await);
        }
        snapshots.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        snapshots
    }
}

impl CoreSession {
    pub fn user_id(&self) -> &str {
        &self.inner.user.id
    }

    pub async fn record_upload(&self, bytes: usize) -> Result<()> {
        self.inner.user.record_upload(bytes).await
    }

    pub async fn record_download(&self, bytes: usize) -> Result<()> {
        self.inner.user.record_download(bytes).await
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.user.online.fetch_sub(1, Ordering::SeqCst);
    }
}

impl UserState {
    async fn record_upload(&self, bytes: usize) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.ensure_quota(bytes as u64).await?;
        self.upload_limiter.lock().await.wait(bytes as u64).await;
        self.upload.fetch_add(bytes as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn record_download(&self, bytes: usize) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.ensure_quota(bytes as u64).await?;
        self.download_limiter.lock().await.wait(bytes as u64).await;
        self.download.fetch_add(bytes as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn ensure_quota(&self, bytes: u64) -> Result<()> {
        let limits = *self.limits.read().expect("core limits lock poisoned");
        if let Some(quota) = limits.quota_bytes {
            let used = self
                .upload
                .load(Ordering::Relaxed)
                .saturating_add(self.download.load(Ordering::Relaxed));
            if used.saturating_add(bytes) > quota {
                bail!("traffic quota exceeded for user {}", self.id);
            }
        }
        Ok(())
    }

    async fn snapshot(&self) -> TrafficSnapshot {
        let upload = self.upload.load(Ordering::Relaxed);
        let download = self.download.load(Ordering::Relaxed);
        let quota = self
            .limits
            .read()
            .expect("core limits lock poisoned")
            .quota_bytes;
        TrafficSnapshot {
            user_id: self.id.clone(),
            upload_bytes: upload,
            download_bytes: download,
            online_sessions: self.online.load(Ordering::Relaxed),
            quota_bytes: quota,
            quota_remaining_bytes: quota.map(|quota| quota.saturating_sub(upload + download)),
        }
    }
}

impl ByteRateLimiter {
    fn new(bytes_per_second: Option<u64>) -> Self {
        Self {
            bytes_per_second,
            next: Instant::now(),
        }
    }

    fn set_rate(&mut self, bytes_per_second: Option<u64>) {
        self.bytes_per_second = bytes_per_second;
        self.next = Instant::now();
    }

    async fn wait(&mut self, bytes: u64) {
        let Some(rate) = self.bytes_per_second.filter(|rate| *rate > 0) else {
            return;
        };
        let now = Instant::now();
        if self.next < now {
            self.next = now;
        }
        self.next += Duration::from_secs_f64(bytes as f64 / rate as f64);
        tokio::time::sleep_until(self.next).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_per_user_traffic() -> Result<()> {
        let core = ProxyCore::new(vec![CoreUser::password("u1", "secret")])?;
        let session = core.authenticate("secret").await?;
        session.record_upload(10).await?;
        session.record_download(20).await?;
        let stats = core.snapshot().await;
        assert_eq!(stats[0].upload_bytes, 10);
        assert_eq!(stats[0].download_bytes, 20);
        assert_eq!(stats[0].online_sessions, 1);
        drop(session);
        assert_eq!(core.snapshot().await[0].online_sessions, 0);
        Ok(())
    }

    #[tokio::test]
    async fn quota_rejects_over_limit() -> Result<()> {
        let mut user = CoreUser::password("u1", "secret");
        user.quota_bytes = Some(4);
        let core = ProxyCore::new(vec![user])?;
        let session = core.authenticate("secret").await?;
        session.record_upload(4).await?;
        assert!(session.record_download(1).await.is_err());
        Ok(())
    }
}
