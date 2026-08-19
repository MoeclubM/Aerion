use anyhow::{Context, Result, ensure};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio::task::JoinHandle;
use tproxy_config::IpCidr;
use tun2proxy::{ArgProxy, Args};

pub use tun2proxy::{
    ArgDns as TunDnsStrategy, ArgVerbosity as TunVerbosity,
    CancellationToken as TunCancellationToken,
};

pub const DEFAULT_TUN_MTU: u16 = tun2proxy::DEFAULT_MTU;

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub proxy_url: String,
    pub tun_name: Option<String>,
    pub tun_fd: Option<i32>,
    pub close_fd_on_drop: bool,
    pub setup: bool,
    pub mtu: u16,
    pub packet_information: bool,
    pub dns: TunDnsStrategy,
    pub dns_addr: IpAddr,
    pub virtual_dns_pool: String,
    pub bypass: Vec<String>,
    pub ipv6: bool,
    pub verbosity: TunVerbosity,
    pub tcp_timeout_secs: u64,
    pub udp_timeout_secs: u64,
    pub max_sessions: usize,
    pub exit_on_fatal_error: bool,
}

pub struct TunRuntime {
    shutdown: TunCancellationToken,
    task: JoinHandle<Result<usize>>,
}

impl TunConfig {
    pub fn new(proxy_url: impl Into<String>) -> Self {
        Self {
            proxy_url: proxy_url.into(),
            tun_name: None,
            tun_fd: None,
            close_fd_on_drop: false,
            setup: cfg!(not(target_os = "linux")),
            mtu: DEFAULT_TUN_MTU,
            packet_information: cfg!(any(target_os = "macos", target_os = "ios")),
            dns: TunDnsStrategy::Direct,
            dns_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            virtual_dns_pool: "198.18.0.0/15".to_string(),
            bypass: Vec::new(),
            ipv6: false,
            verbosity: TunVerbosity::Info,
            tcp_timeout_secs: 600,
            udp_timeout_secs: 10,
            max_sessions: 200,
            exit_on_fatal_error: false,
        }
    }

    pub fn ios_packet_flow_socket_fd(
        proxy_url: impl Into<String>,
        tun_fd: i32,
        close_fd_on_drop: bool,
    ) -> Self {
        let mut config = Self::new(proxy_url);
        config.tun_fd = Some(tun_fd);
        config.close_fd_on_drop = close_fd_on_drop;
        config.packet_information = true;
        config.setup = false;
        config
    }

    fn to_tun2proxy_args(&self) -> Result<Args> {
        ensure!(
            !(self.tun_name.is_some() && self.tun_fd.is_some()),
            "TUN interface name and TUN file descriptor are mutually exclusive"
        );
        let proxy = ArgProxy::try_from(self.proxy_url.as_str())
            .map_err(|error| anyhow::anyhow!("parse TUN proxy URL: {error}"))?;
        let mut args = Args::default();
        args.proxy(proxy)
            .dns(self.dns)
            .dns_addr(self.dns_addr)
            .ipv6_enabled(self.ipv6)
            .setup(self.setup)
            .verbosity(self.verbosity);
        if let Some(tun_name) = &self.tun_name {
            args.tun(tun_name.clone());
        }

        #[cfg(unix)]
        if let Some(tun_fd) = self.tun_fd {
            args.tun_fd(Some(tun_fd))
                .close_fd_on_drop(self.close_fd_on_drop);
        }
        #[cfg(not(unix))]
        ensure!(
            self.tun_fd.is_none(),
            "TUN file descriptors are only supported on Unix targets"
        );

        args.virtual_dns_pool = IpCidr::from_str(&self.virtual_dns_pool)
            .with_context(|| format!("parse TUN virtual DNS pool {}", self.virtual_dns_pool))?;
        for bypass in &self.bypass {
            args.bypass(
                IpCidr::from_str(bypass)
                    .with_context(|| format!("parse TUN bypass route {bypass}"))?,
            );
        }
        args.tcp_timeout = self.tcp_timeout_secs;
        args.udp_timeout = self.udp_timeout_secs;
        args.max_sessions = self.max_sessions;
        args.exit_on_fatal_error = self.exit_on_fatal_error;
        Ok(args)
    }
}

impl TunRuntime {
    pub fn shutdown_token(&self) -> TunCancellationToken {
        self.shutdown.clone()
    }

    pub async fn wait(self) -> Result<usize> {
        self.task.await.context("join TUN runtime task")?
    }

    pub async fn stop(self) -> Result<usize> {
        self.shutdown.cancel();
        self.wait().await
    }
}

pub fn socks_proxy_url(addr: SocketAddr) -> String {
    format!("socks5://{addr}")
}

pub async fn run_tun(config: TunConfig, shutdown: TunCancellationToken) -> Result<usize> {
    let args = config.to_tun2proxy_args()?;
    tun2proxy::general_run_async(args, config.mtu, config.packet_information, shutdown)
        .await
        .context("run TUN proxy")
}

pub fn spawn_tun(config: TunConfig) -> Result<TunRuntime> {
    let args = config.to_tun2proxy_args()?;
    let mtu = config.mtu;
    let packet_information = config.packet_information;
    let shutdown = TunCancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        tun2proxy::general_run_async(args, mtu, packet_information, task_shutdown)
            .await
            .context("run TUN proxy")
    });
    Ok(TunRuntime { shutdown, task })
}

#[cfg(test)]
mod tests;
