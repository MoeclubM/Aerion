use crate::protocol::{ProxyTarget, target_name};
use crate::routing::{RouteDecision, RouteNetwork, RouteTable};
use crate::socket_protect;
use crate::socks::{self, SocksRequest};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct RouteProxyConfig {
    pub routes: RouteTable,
    pub upstreams: BTreeMap<String, SocketAddr>,
}

pub async fn run_route_proxy(listener: TcpListener, config: RouteProxyConfig) -> Result<()> {
    let routes = Arc::new(config.routes);
    let upstreams = Arc::new(config.upstreams);
    tracing::info!(
        "route proxy listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener.accept().await.context("accept route client")?;
        let routes = routes.clone();
        let upstreams = upstreams.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_route_client(stream, routes, upstreams).await {
                tracing::warn!("route client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_route_client(
    mut local: TcpStream,
    routes: Arc<RouteTable>,
    upstreams: Arc<BTreeMap<String, SocketAddr>>,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let decision = routes.decide(&target, RouteNetwork::Tcp);
            match decision {
                RouteDecision::Direct => {
                    let mut remote = match connect_direct(&target).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = socks::write_reply(&mut local, 0x01).await;
                            return Err(error);
                        }
                    };
                    socks::write_reply(&mut local, 0x00).await?;
                    tracing::info!("routing {} direct", target_name(&target));
                    copy_bidirectional(&mut local, &mut remote)
                        .await
                        .context("relay direct route")?;
                    Ok(())
                }
                RouteDecision::Block => {
                    socks::write_reply(&mut local, 0x02).await?;
                    bail!("route blocked {}", target_name(&target))
                }
                RouteDecision::Proxy(tag) => {
                    let upstream = *upstreams
                        .get(&tag)
                        .with_context(|| format!("route outbound {tag} was not started"))?;
                    let mut remote = match socks::connect_tcp(upstream, &target).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = socks::write_reply(&mut local, 0x05).await;
                            return Err(error);
                        }
                    };
                    socks::write_reply(&mut local, 0x00).await?;
                    tracing::info!("routing {} via {tag}", target_name(&target));
                    copy_bidirectional(&mut local, &mut remote)
                        .await
                        .with_context(|| format!("relay route via {tag}"))?;
                    Ok(())
                }
            }
        }
        SocksRequest::UdpAssociate => {
            socks::write_reply(&mut local, 0x07).await?;
            bail!("route proxy does not implement SOCKS UDP ASSOCIATE yet")
        }
    }
}

async fn connect_direct(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => socket_protect::connect_tcp_addr(*addr).await,
        ProxyTarget::Domain(host, port) => socket_protect::connect_tcp_host_port(host, *port).await,
    }
}
