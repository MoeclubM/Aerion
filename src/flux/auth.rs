use super::frame::{FluxFrame, encode_frame_body};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const HELLO_CLOCK_SKEW_SECS: u64 = 180;
pub const HELLO_REPLAY_TTL_SECS: u64 = HELLO_CLOCK_SKEW_SECS * 2 + 1;

pub fn derive_blind_key(secret: &[u8], session_id: &[u8; 16], nonce: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(session_id), secret);
    let mut info = b"flux-v2-credential-mask".to_vec();
    info.extend_from_slice(nonce);
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|_| anyhow::anyhow!("derive Flux credential mask"))?;
    Ok(out)
}

pub fn handshake_key(
    blind_key: &[u8; 32],
    credential: &[u8; 32],
    binding: &[u8; 32],
) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(credential), blind_key);
    let mut info = b"flux-v2-channel-auth".to_vec();
    info.extend_from_slice(binding);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| anyhow::anyhow!("derive Flux channel authentication key"))?;
    Ok(key)
}

fn proof(key: &[u8; 32], role: &[u8], hello: &FluxFrame, response: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("initialize Flux authentication proof"))?;
    mac.update(role);
    mac.update(&encode_frame_body(hello)?);
    mac.update(response);
    Ok(mac.finalize().into_bytes().into())
}

pub fn client_proof(key: &[u8; 32], hello: &FluxFrame) -> Result<[u8; 32]> {
    let mut unsigned = hello.clone();
    let FluxFrame::SessionHello { client_proof, .. } = &mut unsigned else {
        anyhow::bail!("Flux authentication requires SessionHello");
    };
    *client_proof = [0; 32];
    proof(key, b"flux-v2-client", &unsigned, &[])
}

pub fn server_proof(key: &[u8; 32], hello: &FluxFrame, udp_enabled: bool) -> Result<[u8; 32]> {
    ensure!(
        matches!(hello, FluxFrame::SessionHello { .. }),
        "expected Flux SessionHello"
    );
    proof(key, b"flux-v2-server", hello, &[0, u8::from(udp_enabled)])
}

pub fn xor_32(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    std::array::from_fn(|i| left[i] ^ right[i])
}
