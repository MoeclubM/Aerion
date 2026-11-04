# Flux

Flux aggregates TCP, QUIC and HTTP transport channels into one authenticated logical session. Stream offsets, acknowledgements and replay buffers preserve the target TCP socket when a physical channel is replaced. Server process restarts and loss of all paths beyond the session retention period cannot preserve target sockets.

## Client compatibility

`type: flux` is an Aerion extension using the Clash YAML envelope. Stock Mihomo and Clash do not implement this protocol. Panels must filter Flux before producing their proxy entries and group membership for ordinary clients. `types=all` and `format=clash` do not declare Flux support. An explicit `types=...,flux`, `X-XBClient-Protocols: ...,flux`, or an Aerion/XBClient identity declares support. An explicit supported-protocol list that excludes Flux takes precedence over the user agent.

Public subscriptions contain only dialing parameters. Listener addresses, local ports, certificate paths, private keys and fallback destinations belong exclusively to the authenticated node configuration API. Both panels must resolve inherited public keys, Short IDs and security settings consistently with NodeRS. An empty per-channel Short ID inherits the node value even when the channel uses an independent private key.

## Authentication

Wire version 2 is required; version 1 is rejected. Deploy the matching Aerion dependency on NodeRS and XBClient together.

REALITY channels derive a credential mask from a fresh X25519 exchange with the configured server public key. Obfuscation channels use their configured shared secret. TLS channels rely on normal certificate authentication. Credentials travel inside these protected channels, with a separate HKDF output used for authentication proofs; the transmitted masked credential is never an authentication key.

Client and server proofs use separate HMAC domain labels and cover the complete SessionHello, including timestamp, session identity, channel identity, masked credential and client proof. The server response also authenticates the advertised UDP capability. For every QUIC channel, the mask/proof derivation includes a TLS exporter value unique to that QUIC connection. Relaying the authentication exchange over a second TLS connection therefore fails. This is essential for the application-authenticated QUIC modes that use ephemeral self-signed certificates.

The QUIC SCID filter is an admission/presentation filter, not server authentication: its inputs are available in a subscription. Only the version 2 proof validates server identity. QUIC mode uses an ephemeral certificate for accepted Flux sessions and forwards unauthorized probes to the configured origin where enabled; it does not present the origin's certificate to an authenticated Flux client. Obfuscation alone is not encryption; packet contents remain protected by QUIC, while stream obfuscation uses an authenticated encrypted stream.

Authentication failures do not consume the successful-hello replay cache. Successful records live for the full accepted timestamp span, including the future timestamp allowance. UDP sockets preserve destination-address metadata and use the same local source address for replies under wildcard listening.

## Channel lifetime and scheduling

`listen_ip` may be omitted to use the node's wildcard listener. Entry addresses and local binding addresses are independent.

The pool maintains `1 + standby_channels` usable physical channels, limited only by available configured entrances and the documented configuration bounds. Backup-role channels are used for new business streams only when no primary channel is usable. Failed entrances receive exponential retry delays of 2–32 seconds; remaining entrances continue filling the pool. Redialing does not suspend heartbeat expiry.

PING replies must match the outstanding sequence and timestamp. A missing reply with no other incoming traffic expires after three smoothed round trips, with a 600 ms floor. A separate 200 ms maintenance tick observes that deadline, including during downloads with no outstanding upload. Latency-based degradation additionally requires a measured throughput decrease; these are routing signals, not proof of carrier throttling, and cannot guarantee bypass of network policies.

Physical channel send queues are bounded and interruptible. A blocked queue cannot prevent the owning stream from observing migration. Unacknowledged data remains buffered for replay. Windows start at 256 KiB and grow on acknowledgement under load, up to 8 MiB per direction per active stream; storage is allocated for actual buffered bytes. This trades memory for throughput on long-delay links.

Stopping or cancelling a client listener cancels its owned maintenance and business tasks and closes both TCP and QUIC channel I/O. This also applies to one-shot latency probes.

## Server reloads

NodeRS owns `FluxServerState` independently of a listener generation. Replacing listeners or certificates preserves the logical session registry, replay records, target sockets, rate limiters and traffic counters. Existing accepted TCP channels can drain; QUIC channels reconnect and resume against the same state. A configuration update may briefly pause traffic during rebinding. Final node shutdown and revoked user credentials still cancel sessions deliberately.

## Resolution

Clients resolve only effective enabled entrances before route interception. A and AAAA queries run independently. A failed family or entrance is logged, and that entrance is marked unavailable for the current connection attempt while other resolved entrances remain usable. If no entrance has a usable address, connection startup reports an error. The original domain remains the TLS/REALITY server name, and resolved addresses are used for dialing and route exclusions.
