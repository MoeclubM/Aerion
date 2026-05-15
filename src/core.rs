use anyhow::{Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::Notify;
use tokio::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreUser {
    pub id: String,
    pub credential: String,
    pub upload_limit_bps: Option<u64>,
    pub download_limit_bps: Option<u64>,
    pub quota_bytes: Option<u64>,
    pub max_online_sessions: Option<u64>,
    pub max_online_ips: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoreUserLimits {
    pub upload_limit_bps: Option<u64>,
    pub download_limit_bps: Option<u64>,
    pub quota_bytes: Option<u64>,
    pub max_online_sessions: Option<u64>,
    pub max_online_ips: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrafficSnapshot {
    pub user_id: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub online_sessions: u64,
    pub online_ips: u64,
    pub online_ip_list: Vec<String>,
    pub quota_bytes: Option<u64>,
    pub quota_remaining_bytes: Option<u64>,
    pub max_online_sessions: Option<u64>,
    pub max_online_ips: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ProxyCore {
    inner: Arc<CoreInner>,
}

#[derive(Debug, Default)]
struct CoreInner {
    users: RwLock<HashMap<String, Arc<UserState>>>,
    credentials: RwLock<HashMap<String, String>>,
    session_seq: AtomicU64,
}

#[derive(Debug)]
struct UserState {
    id: String,
    credential: RwLock<String>,
    upload: AtomicU64,
    download: AtomicU64,
    online: AtomicU64,
    online_ips: AtomicU64,
    limits: RwLock<CoreUserLimits>,
    upload_limiter: ByteRateLimiter,
    download_limiter: ByteRateLimiter,
    sessions: Mutex<HashMap<u64, SessionSlot>>,
}

#[derive(Debug)]
struct ActiveSession {
    user: Arc<UserState>,
    session_id: u64,
    control: Arc<SessionControl>,
}

#[derive(Clone, Debug)]
pub struct CoreSession {
    inner: Arc<ActiveSession>,
}

#[derive(Debug)]
struct ByteRateLimiter {
    bytes_per_second: AtomicU64,
    next: Mutex<Instant>,
}

struct SessionControl {
    cancelled: AtomicBool,
    notify: Notify,
}

#[derive(Clone, Debug)]
struct SessionSlot {
    control: Arc<SessionControl>,
    source_ip: Option<String>,
}

impl CoreUser {
    pub fn password(id: impl Into<String>, credential: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            credential: credential.into(),
            upload_limit_bps: None,
            download_limit_bps: None,
            quota_bytes: None,
            max_online_sessions: None,
            max_online_ips: None,
        }
    }

    fn limits(&self) -> CoreUserLimits {
        CoreUserLimits {
            upload_limit_bps: self.upload_limit_bps,
            download_limit_bps: self.download_limit_bps,
            quota_bytes: self.quota_bytes,
            max_online_sessions: self.max_online_sessions,
            max_online_ips: self.max_online_ips,
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
        let mut credentials = HashSet::new();
        for user in &users {
            ensure!(!user.id.trim().is_empty(), "core user id is empty");
            ensure!(
                !user.credential.trim().is_empty(),
                "core user credential is empty"
            );
            ensure!(
                credentials.insert(user.credential.clone()),
                "duplicate core credential for user {}",
                user.id
            );
        }

        let current_users = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .clone();
        let mut user_map = HashMap::new();
        let mut credential_map = HashMap::new();
        let mut active_ids = HashSet::new();
        for user in users {
            active_ids.insert(user.id.clone());
            credential_map.insert(user.credential.clone(), user.id.clone());
            let state = if let Some(existing) = current_users.get(&user.id) {
                existing.apply_user_update(&user);
                existing.clone()
            } else {
                Arc::new(UserState::new(&user))
            };
            user_map.insert(user.id.clone(), state);
        }
        for (id, state) in current_users {
            if !active_ids.contains(&id) {
                state.cancel_sessions();
            }
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
        self.authenticate_with_source(credential, None).await
    }

    pub async fn authenticate_from(
        &self,
        credential: &str,
        source: SocketAddr,
    ) -> Result<CoreSession> {
        self.authenticate_with_source(credential, Some(source.ip()))
            .await
    }

    async fn authenticate_with_source(
        &self,
        credential: &str,
        source_ip: Option<IpAddr>,
    ) -> Result<CoreSession> {
        let credential = credential.trim();
        let user_id = self
            .inner
            .credentials
            .read()
            .expect("core credentials lock poisoned")
            .get(credential)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("core authentication failed"))?;
        self.open_session_with_source(&user_id, source_ip).await
    }

    pub async fn open_session(&self, user_id: &str) -> Result<CoreSession> {
        self.open_session_with_source(user_id, None).await
    }

    pub async fn open_session_from(
        &self,
        user_id: &str,
        source: SocketAddr,
    ) -> Result<CoreSession> {
        self.open_session_with_source(user_id, Some(source.ip()))
            .await
    }

    async fn open_session_with_source(
        &self,
        user_id: &str,
        source_ip: Option<IpAddr>,
    ) -> Result<CoreSession> {
        let user = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .get(user_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("core user not found: {user_id}"))?;
        let session_id = self.inner.session_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let control = user.open_session(session_id, source_ip)?;
        Ok(CoreSession {
            inner: Arc::new(ActiveSession {
                user,
                session_id,
                control,
            }),
        })
    }

    pub fn cancel_user_sessions(&self, user_id: &str) -> Result<()> {
        let user = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .get(user_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("core user not found: {user_id}"))?;
        user.cancel_sessions();
        Ok(())
    }

    pub fn cancel_all_sessions(&self) {
        let users = self
            .inner
            .users
            .read()
            .expect("core users lock poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for user in users {
            user.cancel_sessions();
        }
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
        user.upload_limiter.set_rate(limits.upload_limit_bps);
        user.download_limiter.set_rate(limits.download_limit_bps);
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
            snapshots.push(user.snapshot());
        }
        snapshots.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        snapshots
    }
}

impl CoreSession {
    pub fn user_id(&self) -> &str {
        &self.inner.user.id
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.control.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.inner.control.cancelled().await;
    }

    pub async fn record_upload(&self, bytes: usize) -> Result<()> {
        self.inner
            .user
            .record_upload(bytes, &self.inner.control)
            .await
    }

    pub async fn record_download(&self, bytes: usize) -> Result<()> {
        self.inner
            .user
            .record_download(bytes, &self.inner.control)
            .await
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.user.close_session(self.session_id);
    }
}

impl UserState {
    fn new(user: &CoreUser) -> Self {
        Self {
            id: user.id.clone(),
            credential: RwLock::new(user.credential.clone()),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            online: AtomicU64::new(0),
            online_ips: AtomicU64::new(0),
            limits: RwLock::new(user.limits()),
            upload_limiter: ByteRateLimiter::new(user.upload_limit_bps),
            download_limiter: ByteRateLimiter::new(user.download_limit_bps),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn apply_user_update(&self, user: &CoreUser) {
        let old_credential = self
            .credential
            .read()
            .expect("core credential lock poisoned")
            .clone();
        if old_credential != user.credential {
            self.cancel_sessions();
            *self
                .credential
                .write()
                .expect("core credential lock poisoned") = user.credential.clone();
        }
        let limits = user.limits();
        *self.limits.write().expect("core limits lock poisoned") = limits;
        self.upload_limiter.set_rate(limits.upload_limit_bps);
        self.download_limiter.set_rate(limits.download_limit_bps);
    }

    fn open_session(
        &self,
        session_id: u64,
        source_ip: Option<IpAddr>,
    ) -> Result<Arc<SessionControl>> {
        let limits = *self.limits.read().expect("core limits lock poisoned");
        let mut sessions = self.sessions.lock().expect("core sessions lock poisoned");
        if let Some(limit) = limits.max_online_sessions.filter(|limit| *limit > 0) {
            ensure!(
                (sessions.len() as u64) < limit,
                "online session limit exceeded for user {}",
                self.id
            );
        }
        let source_ip = source_ip.map(normalize_ip);
        if let (Some(limit), Some(source_ip)) =
            (limits.max_online_ips.filter(|limit| *limit > 0), &source_ip)
        {
            let mut online_ips = sessions
                .values()
                .filter_map(|slot| slot.source_ip.as_deref())
                .collect::<HashSet<_>>();
            if !online_ips.contains(source_ip.as_str()) {
                online_ips.insert(source_ip.as_str());
                ensure!(
                    (online_ips.len() as u64) <= limit,
                    "online IP limit exceeded for user {}",
                    self.id
                );
            }
        }
        let control = Arc::new(SessionControl::new());
        sessions.insert(
            session_id,
            SessionSlot {
                control: control.clone(),
                source_ip,
            },
        );
        self.update_online_counts(&sessions);
        Ok(control)
    }

    fn close_session(&self, session_id: u64) {
        let mut sessions = self.sessions.lock().expect("core sessions lock poisoned");
        sessions.remove(&session_id);
        self.update_online_counts(&sessions);
    }

    fn cancel_sessions(&self) {
        let sessions = {
            let mut guard = self.sessions.lock().expect("core sessions lock poisoned");
            let sessions = guard
                .values()
                .map(|slot| slot.control.clone())
                .collect::<Vec<_>>();
            guard.clear();
            self.online.store(0, Ordering::SeqCst);
            self.online_ips.store(0, Ordering::SeqCst);
            sessions
        };
        for session in sessions {
            session.cancel();
        }
    }

    fn update_online_counts(&self, sessions: &HashMap<u64, SessionSlot>) {
        self.online.store(sessions.len() as u64, Ordering::SeqCst);
        self.online_ips.store(
            sessions
                .values()
                .filter_map(|slot| slot.source_ip.as_deref())
                .collect::<HashSet<_>>()
                .len() as u64,
            Ordering::SeqCst,
        );
    }

    async fn record_upload(&self, bytes: usize, control: &SessionControl) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        control.ensure_active()?;
        self.ensure_quota(bytes as u64)?;
        self.upload_limiter.wait(bytes as u64, control).await?;
        control.ensure_active()?;
        self.upload.fetch_add(bytes as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn record_download(&self, bytes: usize, control: &SessionControl) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        control.ensure_active()?;
        self.ensure_quota(bytes as u64)?;
        self.download_limiter.wait(bytes as u64, control).await?;
        control.ensure_active()?;
        self.download.fetch_add(bytes as u64, Ordering::Relaxed);
        Ok(())
    }

    fn ensure_quota(&self, bytes: u64) -> Result<()> {
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

    fn snapshot(&self) -> TrafficSnapshot {
        let upload = self.upload.load(Ordering::Relaxed);
        let download = self.download.load(Ordering::Relaxed);
        let limits = *self.limits.read().expect("core limits lock poisoned");
        let online_ip_list = self.online_ip_list();
        TrafficSnapshot {
            user_id: self.id.clone(),
            upload_bytes: upload,
            download_bytes: download,
            online_sessions: self.online.load(Ordering::Relaxed),
            online_ips: self.online_ips.load(Ordering::Relaxed),
            online_ip_list,
            quota_bytes: limits.quota_bytes,
            quota_remaining_bytes: limits
                .quota_bytes
                .map(|quota| quota.saturating_sub(upload + download)),
            max_online_sessions: limits.max_online_sessions,
            max_online_ips: limits.max_online_ips,
        }
    }

    fn online_ip_list(&self) -> Vec<String> {
        let sessions = self.sessions.lock().expect("core sessions lock poisoned");
        let mut ips = sessions
            .values()
            .filter_map(|slot| slot.source_ip.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ips.sort();
        ips
    }
}

impl ByteRateLimiter {
    fn new(bytes_per_second: Option<u64>) -> Self {
        Self {
            bytes_per_second: AtomicU64::new(rate_value(bytes_per_second)),
            next: Mutex::new(Instant::now()),
        }
    }

    fn set_rate(&self, bytes_per_second: Option<u64>) {
        let bytes_per_second = rate_value(bytes_per_second);
        let previous = self
            .bytes_per_second
            .swap(bytes_per_second, Ordering::Relaxed);
        if previous != bytes_per_second {
            *self.next.lock().expect("core limiter lock poisoned") = Instant::now();
        }
    }

    async fn wait(&self, bytes: u64, control: &SessionControl) -> Result<()> {
        let rate = self.bytes_per_second.load(Ordering::Relaxed);
        if bytes == 0 || rate == 0 {
            return Ok(());
        }
        let wait_until = {
            let mut next = self.next.lock().expect("core limiter lock poisoned");
            let now = Instant::now();
            if *next < now {
                *next = now;
            }
            *next += Duration::from_secs_f64(bytes as f64 / rate as f64);
            *next
        };
        tokio::select! {
            _ = control.cancelled() => bail!("core session cancelled"),
            _ = tokio::time::sleep_until(wait_until) => Ok(()),
        }
    }
}

impl SessionControl {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }

    fn ensure_active(&self) -> Result<()> {
        ensure!(!self.is_cancelled(), "core session cancelled");
        Ok(())
    }
}

impl std::fmt::Debug for SessionControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionControl")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

fn rate_value(bytes_per_second: Option<u64>) -> u64 {
    bytes_per_second.filter(|rate| *rate > 0).unwrap_or(0)
}

fn normalize_ip(ip: IpAddr) -> String {
    ip.to_string().trim_start_matches("::ffff:").to_string()
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
        assert_eq!(stats[0].online_ips, 0);
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

    #[tokio::test]
    async fn online_limit_rejects_extra_sessions() -> Result<()> {
        let mut user = CoreUser::password("u1", "secret");
        user.max_online_sessions = Some(1);
        let core = ProxyCore::new(vec![user])?;
        let session = core.authenticate("secret").await?;
        assert!(core.authenticate("secret").await.is_err());
        drop(session);
        let session = core.authenticate("secret").await?;
        assert_eq!(session.user_id(), "u1");
        Ok(())
    }

    #[tokio::test]
    async fn online_ip_limit_counts_unique_sources() -> Result<()> {
        let mut user = CoreUser::password("u1", "secret");
        user.max_online_ips = Some(1);
        let core = ProxyCore::new(vec![user])?;
        let first = core
            .authenticate_from("secret", "1.1.1.1:1000".parse()?)
            .await?;
        let second = core
            .authenticate_from("secret", "1.1.1.1:2000".parse()?)
            .await?;
        assert!(
            core.authenticate_from("secret", "2.2.2.2:1000".parse()?)
                .await
                .is_err()
        );
        let stats = core.snapshot().await;
        assert_eq!(stats[0].online_sessions, 2);
        assert_eq!(stats[0].online_ips, 1);
        drop(first);
        drop(second);
        let third = core
            .authenticate_from("secret", "2.2.2.2:1000".parse()?)
            .await?;
        assert_eq!(third.user_id(), "u1");
        Ok(())
    }

    #[tokio::test]
    async fn replace_users_preserves_traffic_and_cancels_rotated_sessions() -> Result<()> {
        let core = ProxyCore::new(vec![CoreUser::password("u1", "old-secret")])?;
        let session = core.authenticate("old-secret").await?;
        session.record_upload(10).await?;
        core.replace_users(vec![CoreUser::password("u1", "new-secret")])?;
        assert!(session.is_cancelled());
        assert!(session.record_upload(1).await.is_err());
        assert!(core.authenticate("old-secret").await.is_err());
        let new_session = core.authenticate("new-secret").await?;
        assert_eq!(new_session.user_id(), "u1");
        let stats = core.snapshot().await;
        assert_eq!(stats[0].upload_bytes, 10);
        Ok(())
    }

    #[tokio::test]
    async fn supports_multiple_credentials_for_one_user() -> Result<()> {
        let core = ProxyCore::new(vec![
            CoreUser::password("u1", "secret-a"),
            CoreUser::password("u1", "secret-b"),
        ])?;
        assert_eq!(core.authenticate("secret-a").await?.user_id(), "u1");
        assert_eq!(core.authenticate("secret-b").await?.user_id(), "u1");
        Ok(())
    }
}
