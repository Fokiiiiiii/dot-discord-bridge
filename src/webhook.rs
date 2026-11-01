//! Signed MCP Events callbacks. Destination DNS is validated and pinned per request.
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::{Host, Url};

pub fn validate_secret(secret: &str) -> Result<Vec<u8>> {
    let encoded = secret
        .strip_prefix("whsec_")
        .context("Invalid signing secret")?;
    let key = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow!("Invalid signing secret"))?;
    if !(24..=64).contains(&key.len()) {
        bail!("Invalid signing secret length");
    }
    Ok(key)
}

pub fn validate_url(value: &str, hosts: &HashSet<String>) -> Result<Url> {
    // Reject ambiguous strings instead of allowing URL parser normalization of controls.
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) || value.contains('\\') {
        bail!("Invalid callback URL");
    }
    let url = Url::parse(value).map_err(|_| anyhow!("Invalid callback URL"))?;
    let host = match url.host() {
        Some(Host::Domain(h)) => h,
        _ => bail!("IP literal callbacks forbidden"),
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
        || !hosts.contains(host)
    {
        bail!("Callback must use HTTPS and an explicitly allowed hostname");
    }
    Ok(url)
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}
fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Only native global-unicast space; reject all mapped/translation/ULA/link-local
    // addresses and special-purpose allocations, even some globally reachable ones.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x0200)
        && !(s[0] == 0x2001 && s[1] == 0x0db8)
        && s[0] != 0x2002
        && !(s[0] == 0x3fff && s[1] < 0x1000)
}
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => public_v6(v),
    }
}
fn signature(secret: &str, eid: &str, timestamp: &str, body: &[u8]) -> Result<String> {
    let key = validate_secret(secret)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|_| anyhow!("Invalid signing key"))?;
    mac.update(eid.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "v1,{}",
        STANDARD.encode(mac.finalize().into_bytes())
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn post(
    url: &str,
    hosts: &HashSet<String>,
    secret: &str,
    old: Option<&str>,
    sid: &str,
    eid: &str,
    body: &[u8],
    verification: bool,
) -> Result<(u16, Vec<u8>)> {
    if body.len() > 262_144 {
        bail!("Webhook body exceeds 256 KiB");
    }
    let url = validate_url(url, hosts)?;
    let host = url
        .host_str()
        .context("Missing callback hostname")?
        .to_owned();
    let addresses: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), 443)),
    )
    .await
    .map_err(|_| anyhow!("callback_timeout"))?
    .map_err(|_| anyhow!("Callback DNS lookup failed"))?
    .collect();
    if addresses.is_empty() || addresses.iter().any(|a| !is_public(a.ip())) {
        bail!("Non-public callback destination");
    }
    // A new client ensures no connection pool or DNS cache survives this validation.
    // Keep the URL hostname unchanged, preserving TLS certificate and SNI checks.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .resolve_to_addrs(&host, &addresses)
        .build()
        .map_err(|_| anyhow!("Callback client setup failed"))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let mut sig = signature(secret, eid, &ts, body)?;
    if let Some(old) = old {
        sig.push(' ');
        sig.push_str(&signature(old, eid, &ts, body)?);
    }
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("webhook-id", eid)
        .header("webhook-timestamp", ts)
        .header("webhook-signature", sig)
        .header("X-MCP-Subscription-Id", sid)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            anyhow!(if e.is_timeout() {
                "callback_timeout"
            } else {
                "Callback request failed"
            })
        })?;
    finish_response(response, verification).await
}

async fn finish_response(
    mut response: reqwest::Response,
    verification: bool,
) -> Result<(u16, Vec<u8>)> {
    let status = response.status().as_u16();
    // Event acknowledgments depend on status only. Never let an oversized, slow,
    // or broken response body turn permanent 410/413 into a transient retry.
    // Only a successful verification needs its challenge response body.
    if !verification || !(200..300).contains(&status) {
        return Ok((status, Vec::new()));
    }
    let mut response_body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        anyhow!(if e.is_timeout() {
            "callback_timeout"
        } else {
            "Callback response failed"
        })
    })? {
        if response_body.len() + chunk.len() > 65_536 {
            bail!("Callback response too large");
        }
        response_body.extend_from_slice(&chunk);
    }
    Ok((status, response_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_urls_fail_closed() {
        let hosts = HashSet::from(["callback.example".to_owned()]);
        assert!(validate_url("https://callback.example/path?x=1", &hosts).is_ok());
        for value in [
            "http://callback.example/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://callback.example.evil/",
            "https://user@callback.example/",
            "https://callback.example:8443/",
            "https://callback.example/#fragment",
            "https://callback.example\\@evil.example/",
            "https://callback.example\n/",
        ] {
            assert!(validate_url(value, &hosts).is_err(), "{value}");
        }
    }
    #[test]
    fn public_ip_policy() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.31.1.1",
            "192.168.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.2",
            "203.0.113.3",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::a00:1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn secret_validation_and_signature_vector() {
        for value in ["bad", "whsec_!!!!", "whsec_AA=="] {
            assert!(validate_secret(value).is_err());
        }
        let secret = format!("whsec_{}", STANDARD.encode([b'x'; 32]));
        assert_eq!(validate_secret(&secret).unwrap().len(), 32);
        assert_eq!(
            signature(&secret, "event1", "1700000000", b"{\"data\":\"hello\"}").unwrap(),
            "v1,18cjc2sl4khNlYV2Amo7dPYYHtiya/JjkSULcVtBCM8="
        );
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    async fn response(status: u16, body: &[u8], declared: usize) -> reqwest::Response {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bytes = body.to_vec();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await;
            let head = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&bytes).await;
        });
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn permanent_status_survives_oversized_body() {
        for status in [410, 413] {
            let r = response(status, &vec![b'x'; 70000], 70000).await;
            assert_eq!(finish_response(r, false).await.unwrap().0, status);
        }
    }
    #[tokio::test]
    async fn permanent_status_survives_truncated_body() {
        for status in [410, 413] {
            let r = response(status, b"short", 100000).await;
            assert_eq!(finish_response(r, false).await.unwrap().0, status);
        }
    }
    #[tokio::test]
    async fn retry_status_and_success_ignore_body() {
        for status in [204, 429, 503] {
            let r = response(status, b"short", 100000).await;
            assert_eq!(finish_response(r, false).await.unwrap().0, status);
        }
    }
    #[tokio::test]
    async fn permanent_status_does_not_wait_for_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 410 Gone\r\nContent-Length: 100000\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let result =
            tokio::time::timeout(Duration::from_millis(100), finish_response(response, false))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(result.0, 410);
        server.abort();
    }
    #[tokio::test]
    async fn verification_body_is_still_bounded() {
        let r = response(200, &vec![b'x'; 70000], 70000).await;
        assert!(finish_response(r, true).await.is_err());
        let r = response(200, br#"{"challenge":"test"}"#, 20).await;
        assert_eq!(
            finish_response(r, true).await.unwrap().1,
            br#"{"challenge":"test"}"#
        );
    }
}
