mod auth;
mod client;
pub mod config;
pub mod frame;
pub mod obfs;
pub mod reality_udp;
mod server;
pub mod transport;

pub use client::{
    FluxClientPool, run_flux_client, run_flux_client_listener, run_flux_client_listener_with_core,
    run_flux_client_listener_with_core_until,
};
pub use config::{
    DEFAULT_ROTATION_BYTES_MB, DEFAULT_ROTATION_INTERVAL_SEC, DEFAULT_STANDBY_CHANNELS,
    FluxCertMode, FluxChannelClientConfig, FluxChannelRole, FluxChannelServerConfig,
    FluxChannelWireConfig, FluxClientConfig, FluxHttpMode, FluxIpStrategy, FluxOptions,
    FluxRealityWireOpts, FluxSecurityMode, FluxServerConfig, FluxTransportKind,
    MAX_FLUX_EXPANDED_PORTS, PortSpecInput, normalize_ip_version, parse_port_spec,
    parse_transport_and_mode,
};
pub use server::{
    FluxServerState, RunningFluxServer, run_flux_server, run_flux_server_with_core,
    run_flux_server_with_core_until, start_flux_server_with_core,
    start_flux_server_with_core_and_stop, start_flux_server_with_state,
};

#[cfg(test)]
mod regressions;
#[cfg(test)]
mod tests;
