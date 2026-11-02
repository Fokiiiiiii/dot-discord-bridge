//! Coarse, content-free bridge state. This is not a dot/model activity signal.
use crate::{Bridge, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::Instant;

// Conservative local policy: one update per 20 seconds, including across
// reconnects, coalesces rapid changes and leaves Gateway rate-limit headroom.
pub const MIN_INTERVAL: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Connected,
    Queued,
    InboxFailure,
    Unknown,
}

pub fn sample(bridge: &Bridge) -> Presence {
    sample_inner(bridge).unwrap_or(Presence::Unknown)
}

fn sample_inner(bridge: &Bridge) -> Result<Presence> {
    let db = bridge
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("database lock failed"))?;
    let failed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM inbox WHERE status='failed')",
        [],
        |r| r.get(0),
    )?;
    let queued: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM inbox WHERE status='pending') OR EXISTS(SELECT 1 FROM queue)",
        [],
        |r| r.get(0),
    )?;
    Ok(if failed {
        Presence::InboxFailure
    } else if queued {
        Presence::Queued
    } else {
        Presence::Connected
    })
}

pub fn packet(presence: Presence) -> Value {
    let (status, name) = match presence {
        Presence::Connected => ("online", "Bridge connected"),
        Presence::Queued => ("idle", "Bridge work queued"),
        Presence::InboxFailure => ("dnd", "Inbox needs attention"),
        Presence::Unknown => ("dnd", "Bridge status unknown"),
    };
    json!({"op":3,"d":{"since":null,"activities":[{"name":name,"type":0}],"status":status,"afk":false}})
}

#[derive(Default)]
pub struct Limiter {
    last: Option<(Presence, Instant)>,
}
impl Limiter {
    pub fn should_send(&self, desired: Presence, now: Instant, fresh_session: bool) -> bool {
        match self.last {
            None => true,
            Some((previous, at)) => {
                now.saturating_duration_since(at) >= MIN_INTERVAL
                    && (fresh_session || previous != desired)
            }
        }
    }
    pub fn sent(&mut self, desired: Presence, now: Instant) {
        self.last = Some((desired, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_is_static_and_coalesced() {
        for p in [
            Presence::Connected,
            Presence::Queued,
            Presence::InboxFailure,
            Presence::Unknown,
        ] {
            let value = packet(p);
            assert_eq!(value["op"], 3);
            assert!(value["d"]["activities"][0]["name"].as_str().unwrap().len() < 32);
        }
        let now = Instant::now();
        let mut limiter = Limiter::default();
        assert!(limiter.should_send(Presence::Connected, now, true));
        limiter.sent(Presence::Connected, now);
        assert!(!limiter.should_send(Presence::Queued, now + Duration::from_secs(19), false));
        assert!(!limiter.should_send(Presence::Connected, now + Duration::from_secs(20), false));
        assert!(limiter.should_send(Presence::Queued, now + Duration::from_secs(20), false));
        assert!(limiter.should_send(Presence::Connected, now + Duration::from_secs(20), true));
    }
    #[test]
    fn reflects_all_queued_items_and_failure_precedence() {
        let bridge = crate::tests::bridge();
        assert_eq!(sample(&bridge), Presence::Connected);
        {
            let db = bridge.db.lock().unwrap();
            for id in ["a", "b"] {
                db.execute("INSERT INTO inbox(id,channel,author,status,tries,due,received) VALUES(?,'c','a','pending',0,0,0)", [id]).unwrap();
            }
        }
        assert_eq!(sample(&bridge), Presence::Queued);
        bridge
            .db
            .lock()
            .unwrap()
            .execute("UPDATE inbox SET status='done' WHERE id='a'", [])
            .unwrap();
        assert_eq!(sample(&bridge), Presence::Queued);
        bridge
            .db
            .lock()
            .unwrap()
            .execute("UPDATE inbox SET status='failed' WHERE id='b'", [])
            .unwrap();
        assert_eq!(sample(&bridge), Presence::InboxFailure);
        bridge
            .db
            .lock()
            .unwrap()
            .execute("UPDATE inbox SET status='done'", [])
            .unwrap();
        bridge
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO queue(sid,eid,body,due) VALUES('s','e','{}',0)",
                [],
            )
            .unwrap();
        assert_eq!(sample(&bridge), Presence::Queued);
        bridge
            .db
            .lock()
            .unwrap()
            .execute("DROP TABLE inbox", [])
            .unwrap();
        assert_eq!(sample(&bridge), Presence::Unknown);
    }
}
