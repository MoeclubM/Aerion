# Flux

Flux aggregates TCP, QUIC and HTTP transport channels into one authenticated logical session. Stream offsets, acknowledgements and replay buffers preserve the target TCP socket when a physical channel is replaced. Server process restarts and loss of all paths beyond the session retention period cannot preserve target sockets.

## Client compatibility

`type: flux` is an Aerion extension using a YAML envelope compatible with the existing proxy and routing configuration. Stock Mihomo and Clash do not implement this protocol. Panels use a separate Aerion subscription adapter: Xboard selects it with `flag=aerion` / `flag=xbclient`, and PxBoard with `format=aerion` / `format=xbclient` or the matching flag. Without an explicit adapter selection, an Aerion/XBClient identity selects the Aerion adapter. Explicit Mihomo/Clash selection always excludes Flux, even when `types=flux` or a Flux capability header is present. Filtering happens before proxy entries and group membership are produced.

Within the Aerion adapter, an explicit supported-protocol list that excludes Flux takes precedence over the capability header and user agent. `types=all` uses the selected adapter's supported protocols; it never changes adapters. Standard protocol field serializers and YAML templates can be shared without sharing custom protocol admission or Mihomo version requirements.

Public subscriptions contain only dialing parameters. Listener addresses, local ports, certificate paths, private keys and fallback destinations belong exclusively to the authenticated node configuration API. Each `obfs` channel carries an X25519 keypair: the server stores `private_key` and subscriptions emit only `public-key`.

## Authentication

Wire version 2 is required; version 1 is rejected. Deploy the matching Aerion dependency on NodeRS and XBClient together.

On `obfs` channels, each side uses an X25519 keypair (`private_key` on server, `public_key` in client configuration):
- Stream transports (`tcp` / `http`) perform an ephemeral X25519 forward-secret handshake followed by two-stage ChaCha20-Poly1305 AEAD framing with implicit sequence nonces, random early-frame padding and a 65,536-entry replay cache, exporting a 32-byte channel binding.
- QUIC (`udp`) wraps outer UDP datagrams with XChaCha20-Poly1305 (24-byte random nonce and 16-byte tag, dropping unauthenticated packets before QUIC) and keeps QUIC max UDP payload within 1440 bytes.

Inside `SessionHello`, `obfs` channels also perform a fresh X25519 exchange (`client_ephemeral_pub` against the server's `private_key`) combined with the channel binding (`EXPORTER-Flux-v2` on QUIC/TLS or `obfs` handshake binding on stream `obfs`) so holding `public_key` alone does not allow cross-subscriber MITM or unmasking `cred_hash`. Direct `tls` channels extract `EXPORTER-Flux-v2` by default; `tls_binding: false` is reserved for CDN origin-plain HTTP channels (`cert_mode: origin_plain`).

Client and server proofs use separate HMAC domain labels and cover the complete SessionHello, including timestamp, session identity, channel identity, masked credential and client proof. The server response also authenticates the advertised UDP capability. For every QUIC channel, the mask/proof derivation includes a TLS exporter value unique to that QUIC connection. Relaying the authentication exchange over a second TLS connection therefore fails. This is essential for the application-authenticated QUIC modes that use ephemeral self-signed certificates.

The QUIC SCID filter is an admission/presentation filter, not server authentication: its inputs are available in a subscription. Only the version 2 proof validates server identity. QUIC mode uses an ephemeral certificate for accepted Flux sessions and forwards unauthorized probes to the configured origin where enabled; it does not present the origin's certificate to an authenticated Flux client.

Authentication failures do not consume the successful-hello replay cache (65,536 entries). Per-user `SessionHello` attempts are rate-limited (256 per 60 seconds), and active sessions cap concurrent channels (32), streams (1,024) and UDP associations (256). UDP sockets preserve destination-address metadata and use the same local source address for replies under wildcard listening.

## Channel lifetime and scheduling

`listen_ip` may be omitted to use the node's wildcard listener. Entry addresses and local binding addresses are independent.

The pool maintains a baseline of `1 + standby_channels` usable physical channels and multiplexes inner TCP streams and UDP associations within each outer channel by real-time bidirectional throughput (`channel-max-mbps`, default `20` Mbps; `0` disables speed-based splitting). While an active primary channel remains below `channel-max-mbps`, concurrent streams pack onto that channel instead of scattering across idle standbys. Once a channel reaches `channel-max-mbps`, new streams and UDP datagrams overflow to another under-budget channel. When channels cross 75% of the per-channel speed budget, the pool automatically scales out parallel channels (up to 16 stream channels and 4 dedicated UDP relay channels, including parallel connections to the same endpoint); when traffic subsides, idle excess channels older than 15 seconds shrink back toward `1 + standby_channels`. If multiple streams start simultaneously on one channel and ramp past 110% of `channel-max-mbps`, excess streams migrate losslessly via `StreamMigrate` onto under-budget primary channels. Backup-role channels are used for new business streams only when no primary channel is usable. Failed entrances receive exponential retry delays of 2–32 seconds; remaining entrances continue filling the pool. Redialing does not suspend heartbeat expiry.

PING replies must match the outstanding sequence and timestamp. A missing reply with no other incoming traffic expires after three smoothed round trips, with a 600 ms floor. A separate 200 ms maintenance tick observes that deadline, including during downloads with no outstanding upload. Latency-based degradation additionally requires a measured throughput decrease; these are routing signals, not proof of carrier throttling, and cannot guarantee bypass of network policies.

Physical channel send queues are bounded and interruptible. A blocked queue cannot prevent the owning stream from observing migration. Unacknowledged data remains buffered for replay. Windows start at 256 KiB and grow on acknowledgement under load, up to 8 MiB per direction per active stream; storage is allocated for actual buffered bytes. This trades memory for throughput on long-delay links.

Stopping or cancelling a client listener cancels its owned maintenance and business tasks and closes both TCP and QUIC channel I/O. This also applies to one-shot latency probes.

## Server reloads

NodeRS owns `FluxServerState` independently of a listener generation. Replacing listeners or certificates preserves the logical session registry, replay records, target sockets, rate limiters and traffic counters. Existing accepted TCP channels can drain; QUIC channels reconnect and resume against the same state. A configuration update may briefly pause traffic during rebinding. Final node shutdown and revoked user credentials still cancel sessions deliberately.

## Resolution

Clients resolve only effective enabled entrances before route interception. A and AAAA queries run independently. A failed family or entrance is logged, and that entrance is marked unavailable for the current connection attempt while other resolved entrances remain usable. If no entrance has a usable address, connection startup reports an error. The original domain remains the TLS server name, and resolved addresses are used for dialing and route exclusions.
