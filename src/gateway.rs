//! Single-shard Discord Gateway v10 receiver; no token/body logging.
//! Session state survives reconnects, not process restarts. The bridge does not
//! promise replay across downtime. Run exactly one receiver for each bot token.
use anyhow::{anyhow, bail, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{
    sync::mpsc,
    time::{self, Instant, MissedTickBehavior},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 15);

#[derive(Default)]
struct State {
    sequence: Option<u64>,
    session: Option<String>,
    resume_url: Option<String>,
}

fn fatal_close(code: u16) -> bool {
    matches!(code, 4004 | 4010 | 4011 | 4012 | 4013 | 4014)
}
fn reset_close(code: u16) -> bool {
    matches!(code, 1000 | 1001 | 4003 | 4007 | 4009)
}
fn jitter_ms(max: u64) -> u64 {
    // Scheduling jitter only, not a security primitive.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
        % max.max(1)
}
fn gateway_url(raw: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(raw).map_err(|_| anyhow!("Invalid Gateway URL"))?;
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "wss"
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.port(), None | Some(443))
        || !(host == "gateway.discord.gg" || host.ends_with(".discord.gg"))
    {
        bail!("Invalid Gateway URL");
    }
    url.set_query(Some("v=10&encoding=json"));
    url.set_fragment(None);
    Ok(url.to_string())
}
/// Discord expresses Retry-After and retry_after in seconds (possibly fractional).
/// If both are present, wait for the longer duration. Invalid values stop the
/// receiver rather than silently replacing Discord's instruction with a short retry.
fn rate_limit_delay(header: Option<&str>, body: &Value) -> Result<Duration> {
    let mut seconds: Option<f64> = None;
    let mut accept = |value: f64| -> Result<()> {
        // One day is an operational safety ceiling, not a Discord rate limit.
        // Never clamp a longer server delay and retry early: fail closed instead.
        if !value.is_finite() || !(0.0..=86_400.0).contains(&value) {
            bail!("Invalid Discord retry duration; operator review required");
        }
        seconds = Some(seconds.unwrap_or(0.0).max(value));
        Ok(())
    };
    if let Some(header) = header {
        accept(
            header
                .parse::<f64>()
                .map_err(|_| anyhow!("Invalid Discord Retry-After header"))?,
        )?;
    }
    if let Some(value) = body.get("retry_after") {
        accept(
            value
                .as_f64()
                .ok_or_else(|| anyhow!("Invalid Discord retry_after field"))?,
        )?;
    }
    let seconds = seconds.ok_or_else(|| anyhow!("Discord 429 omitted retry duration"))?;
    // Round up, never down. A zero delay gets a small anti-spin floor.
    Ok(Duration::from_millis(
        (seconds * 1000.0).ceil().max(100.0) as u64
    ))
}

fn auth_packet(token: &str, state: &State) -> Value {
    if let (Some(session), Some(sequence)) = (&state.session, state.sequence) {
        json!({"op":6,"d":{"token":token,"session_id":session,"seq":sequence}})
    } else {
        json!({"op":2,"d":{"token":token,"intents":INTENTS,
            "properties":{"os":"linux","browser":"discord-dot-bridge","device":"discord-dot-bridge"}}})
    }
}

enum Outcome {
    Retry(Duration),
    Fatal(&'static str),
}

async fn connection(
    token: &str,
    url: &str,
    state: &mut State,
    tx: &mpsc::Sender<Value>,
) -> Result<Outcome> {
    let (mut ws, _) = time::timeout(Duration::from_secs(30), connect_async(url)).await??;
    let hello = time::timeout(Duration::from_secs(20), ws.next())
        .await?
        .ok_or_else(|| anyhow!("Missing Gateway Hello"))??;
    let hello: Value = serde_json::from_str(hello.to_text()?)?;
    let interval = hello["d"]["heartbeat_interval"].as_u64().unwrap_or(0);
    if hello["op"] != 10 || interval == 0 || interval > 300_000 {
        bail!("Invalid Gateway Hello");
    }
    let mut heartbeat = time::interval_at(
        Instant::now() + Duration::from_millis(jitter_ms(interval)),
        Duration::from_millis(interval),
    );
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut acknowledged = true;
    ws.send(Message::Text(auth_packet(token, state).to_string().into()))
        .await?;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if !acknowledged {
                    // Dropping the socket (not normal close 1000) preserves resume.
                    return Ok(Outcome::Retry(Duration::from_secs(1)));
                }
                acknowledged = false;
                ws.send(Message::Text(json!({"op":1,"d":state.sequence}).to_string().into())).await?;
            }
            incoming = ws.next() => {
                let Some(message) = incoming else {
                    return Ok(Outcome::Retry(Duration::from_secs(1)));
                };
                match message? {
                    Message::Close(frame) => {
                        if let Some(frame) = frame {
                            let code: u16 = frame.code.into();
                            if fatal_close(code) {
                                return Ok(Outcome::Fatal("Discord closed Gateway: check bot token, privileged intents, or shard configuration"));
                            }
                            if reset_close(code) { *state = State::default(); }
                        }
                        return Ok(Outcome::Retry(Duration::from_secs(1)));
                    }
                    Message::Ping(data) => { ws.send(Message::Pong(data)).await?; }
                    Message::Text(text) => {
                        let packet: Value = serde_json::from_str(text.as_ref())?;
                        match packet["op"].as_u64() {
                            Some(11) => acknowledged = true,
                            Some(1) => {
                                ws.send(Message::Text(json!({"op":1,"d":state.sequence}).to_string().into())).await?;
                            }
                            Some(7) => return Ok(Outcome::Retry(Duration::ZERO)),
                            Some(9) => {
                                if packet["d"] != true { *state = State::default(); }
                                return Ok(Outcome::Retry(Duration::from_millis(1_000 + jitter_ms(4_000))));
                            }
                            Some(0) => {
                                match packet["t"].as_str() {
                                    Some("READY") => {
                                        state.session = Some(packet["d"]["session_id"].as_str()
                                            .ok_or_else(|| anyhow!("Missing Gateway session ID"))?.to_owned());
                                        state.resume_url = Some(gateway_url(packet["d"]["resume_gateway_url"].as_str()
                                            .ok_or_else(|| anyhow!("Missing resume Gateway URL"))?)?);
                                    }
                                    Some("MESSAGE_CREATE") => {
                                        // Never block the heartbeat/ACK reader waiting for a full queue.
                                        // Do not advance sequence until the message has been accepted.
                                        match tx.try_send(packet["d"].clone()) {
                                            Ok(()) => (),
                                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                                return Ok(Outcome::Fatal("Message persistence receiver stopped"));
                                            }
                                            Err(mpsc::error::TrySendError::Full(_)) => {
                                                return Ok(Outcome::Retry(Duration::from_secs(2)));
                                            }
                                        }
                                    }
                                    _ => (),
                                }
                                if let Some(sequence) = packet["s"].as_u64() {
                                    state.sequence = Some(sequence);
                                }
                            }
                            _ => (),
                        }
                    }
                    _ => (),
                }
            }
        }
    }
}

/// Forward MESSAGE_CREATE packets to the persistence worker until cancelled.
/// Fatal errors are intentionally generic and never include credentials or URLs.
pub async fn run(token: String, tx: mpsc::Sender<Value>) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let mut state = State::default();
    let mut base_url: Option<String> = None;
    let mut next_identify = Instant::now();
    let mut backoff = 1_u64;
    loop {
        if tx.is_closed() {
            bail!("Message persistence receiver stopped");
        }
        if state.session.is_none() || state.sequence.is_none() {
            time::sleep_until(next_identify).await;
            // Fetch fresh session-start quota before EVERY Identify, not just startup.
            // No automatic identify attempt occurs when Discord reports exhaustion.
            let response = match client
                .get("https://discord.com/api/v10/gateway/bot")
                .header("Authorization", format!("Bot {token}"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(60);
                    continue;
                }
            };
            if matches!(response.status().as_u16(), 401 | 403) {
                bail!("Discord rejected bot authentication");
            }
            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let retry_header = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .map(|value| value.to_str().map(str::to_owned))
                    .transpose()
                    .map_err(|_| anyhow!("Invalid Discord Retry-After header"))?;
                let mut response = response;
                let mut body_bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| anyhow!("Failed reading Discord rate-limit response"))?
                {
                    if body_bytes.len().saturating_add(chunk.len()) > 8192 {
                        bail!("Oversized Discord rate-limit response");
                    }
                    body_bytes.extend_from_slice(&chunk);
                }
                let body: Value = if body_bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&body_bytes)
                        .map_err(|_| anyhow!("Malformed Discord rate-limit response"))?
                };
                time::sleep(rate_limit_delay(retry_header.as_deref(), &body)?).await;
                continue;
            }
            if !response.status().is_success() {
                time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
                continue;
            }
            let discovery: Value = response
                .json()
                .await
                .map_err(|_| anyhow!("Invalid Discord Gateway discovery"))?;
            if discovery["shards"].as_u64().unwrap_or(1) > 1 {
                bail!("This bridge supports a single Discord shard only");
            }
            if discovery["session_start_limit"]["remaining"].as_u64() == Some(0) {
                let reset = discovery["session_start_limit"]["reset_after"]
                    .as_u64()
                    .unwrap_or(60_000);
                time::sleep(Duration::from_millis(reset.max(1_000))).await;
                continue;
            }
            base_url = Some(gateway_url(
                discovery["url"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing Discord Gateway URL"))?,
            )?);
        }
        let url = state
            .resume_url
            .as_ref()
            .or(base_url.as_ref())
            .ok_or_else(|| anyhow!("Missing Gateway endpoint"))?
            .clone();
        let connected_at = Instant::now();
        let outcome = connection(&token, &url, &mut state, &tx).await;
        // Measure from the completed attempt as well, so a slow handshake cannot
        // compress the spacing between actual Identify packets.
        next_identify = Instant::now() + Duration::from_millis(5_100);
        if connected_at.elapsed() > Duration::from_secs(60) {
            backoff = 1;
        }
        match outcome {
            Ok(Outcome::Fatal(message)) => bail!("{message}"),
            Ok(Outcome::Retry(delay)) => time::sleep(delay).await,
            Err(_) => {
                // Never print external exception text: it can contain sensitive data.
                eprintln!("Discord Gateway interrupted; reconnecting");
                time::sleep(Duration::from_millis(backoff * 1_000 + jitter_ms(1_000))).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rate_limit_delays_honor_discord_seconds() {
        assert_eq!(
            rate_limit_delay(None, &json!({"retry_after": 1.125})).unwrap(),
            Duration::from_millis(1125)
        );
        assert_eq!(
            rate_limit_delay(Some("65"), &json!({"retry_after": 64.57})).unwrap(),
            Duration::from_secs(65)
        );
        assert_eq!(
            rate_limit_delay(Some("1"), &json!({"retry_after": 2.0011})).unwrap(),
            Duration::from_millis(2002)
        );
        assert_eq!(
            rate_limit_delay(Some("0.25"), &Value::Null).unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            rate_limit_delay(Some("0"), &Value::Null).unwrap(),
            Duration::from_millis(100)
        );
    }
    #[test]
    fn rate_limit_delays_fail_closed() {
        for invalid in ["-1", "NaN", "inf", "90000", "tomorrow", ""] {
            assert!(rate_limit_delay(Some(invalid), &json!({"retry_after": 1})).is_err());
        }
        for invalid in [
            json!({}),
            json!({"retry_after": -1}),
            json!({"retry_after": "1"}),
            json!({"retry_after": null}),
            json!({"retry_after": 86401}),
        ] {
            assert!(rate_limit_delay(None, &invalid).is_err());
        }
    }
    #[test]
    fn gateway_destination_validation() {
        assert_eq!(
            gateway_url("wss://gateway.discord.gg").unwrap(),
            "wss://gateway.discord.gg/?v=10&encoding=json"
        );
        for invalid in [
            "ws://gateway.discord.gg",
            "wss://localhost",
            "wss://gateway.discord.gg.evil.example",
            "wss://user:secret@gateway.discord.gg",
            "wss://gateway.discord.gg:8443",
        ] {
            assert!(gateway_url(invalid).is_err());
        }
    }
    #[test]
    fn identifies_then_resumes() {
        let mut state = State::default();
        assert_eq!(auth_packet("placeholder", &state)["op"], 2);
        state.session = Some("session".into());
        state.sequence = Some(42);
        let resume = auth_packet("placeholder", &state);
        assert_eq!(resume["op"], 6);
        assert_eq!(resume["d"]["seq"], 42);
    }
    #[test]
    fn close_code_classification() {
        for code in [4004, 4010, 4011, 4012, 4013, 4014] {
            assert!(fatal_close(code));
        }
        for code in [1000, 1001, 4003, 4007, 4009] {
            assert!(reset_close(code));
        }
        assert!(!fatal_close(4000));
        assert!(!reset_close(4000));
    }
}
