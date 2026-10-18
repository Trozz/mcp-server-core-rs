//! Abuse limits: failed sign-in attempts per address and overall, and one-time codes.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failures across all clients within one window after which any client with an attempt of its
/// own in the window (a rejection, or a check still in flight) is blocked. A client with no
/// attempts is not blocked by other people's failures, unless so many addresses are being
/// tracked that the table is full, when untracked addresses are blocked too. The cap keeps an
/// attacker from spreading guesses over many addresses.
const GLOBAL_MAX_FAILURES: usize = 30;
const MAX_TRACKED_KEYS: usize = 10_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Limits failed sign-in attempts: `max` per address (IPv6 by /64) per window, and a global
/// ceiling so guesses spread over many addresses stay bounded too.
pub struct LoginLimiter {
    max: usize,
    window: Duration,
    state: Mutex<LimiterState>,
}

struct LimiterState {
    per_key: HashMap<IpAddr, Vec<Instant>>,
    global: VecDeque<Instant>,
    last_sweep: Instant,
}

fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

impl LimiterState {
    fn prune(&mut self, now: Instant, window: Duration) {
        while self
            .global
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
            self.global.pop_front();
        }
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        self.per_key.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < window);
            !times.is_empty()
        });
    }
}

impl LoginLimiter {
    /// At most `max` failures per address within `window`.
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            state: Mutex::new(LimiterState {
                per_key: HashMap::new(),
                global: VecDeque::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Whether `ip` may not try again yet.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().expect("limiter lock");
        let now = Instant::now();
        self.blocked(&mut state, limiter_key(ip), now)
    }

    fn blocked(&self, state: &mut LimiterState, key: IpAddr, now: Instant) -> bool {
        state.prune(now, self.window);
        let global_full = state.global.len() >= GLOBAL_MAX_FAILURES;
        let Some(times) = state.per_key.get_mut(&key) else {
            // Untracked because the table is full: its attempts only show in the global count.
            return global_full && state.per_key.len() >= MAX_TRACKED_KEYS;
        };
        times.retain(|t| now.duration_since(*t) < self.window);
        times.len() >= self.max || (global_full && !times.is_empty())
    }

    /// Counts a failed attempt from `ip`.
    pub fn record_failure(&self, ip: IpAddr) {
        let mut state = self.state.lock().expect("limiter lock");
        let now = Instant::now();
        state.prune(now, self.window);
        Self::push(&mut state, limiter_key(ip), now);
    }

    fn push(state: &mut LimiterState, key: IpAddr, now: Instant) {
        state.global.push_back(now);
        if state.per_key.len() >= MAX_TRACKED_KEYS && !state.per_key.contains_key(&key) {
            return;
        }
        state.per_key.entry(key).or_default().push(now);
    }

    /// Counts an attempt as a failure before it is checked, so concurrent attempts share the
    /// limit. `None` when the client is blocked. Give the reservation back with [`Self::refund`]
    /// when the attempt turns out not to be a failure.
    pub fn try_reserve(&self, ip: IpAddr) -> Option<Reservation> {
        let mut state = self.state.lock().expect("limiter lock");
        let now = Instant::now();
        let key = limiter_key(ip);
        if self.blocked(&mut state, key, now) {
            return None;
        }
        Self::push(&mut state, key, now);
        Some(Reservation { key, at: now })
    }

    /// Removes a reserved attempt again: it was accepted, or could not be checked.
    pub fn refund(&self, reservation: Reservation) {
        let mut state = self.state.lock().expect("limiter lock");
        if let Some(i) = state.global.iter().rposition(|t| *t == reservation.at) {
            state.global.remove(i);
        }
        if let Some(times) = state.per_key.get_mut(&reservation.key)
            && let Some(i) = times.iter().rposition(|t| *t == reservation.at)
        {
            times.remove(i);
        }
    }
}

/// An attempt counted by [`LoginLimiter::try_reserve`] until it is refunded.
#[derive(Debug)]
#[must_use = "refund the reservation unless the attempt failed"]
pub struct Reservation {
    key: IpAddr,
    at: Instant,
}

/// Remembers the ids (`jti`) of one-time tokens until they expire, so each is used once.
pub struct ReplayGuard {
    used: Mutex<HashMap<String, u64>>,
}

impl ReplayGuard {
    /// Remembers nothing yet.
    pub fn new() -> Self {
        Self {
            used: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this is the first use of `jti`, a token expiring at `exp_unix`.
    pub fn first_use(&self, jti: &str, exp_unix: u64) -> bool {
        let now = jsonwebtoken::get_current_timestamp();
        let mut used = self.used.lock().expect("replay lock");
        // Tokens stay valid for the JWT leeway after `exp`, so remember them that long too.
        used.retain(|_, exp| *exp + crate::jwt::LEEWAY_SECS >= now);
        used.insert(jti.to_string(), exp_unix).is_none()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.used.lock().unwrap().len()
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_after_max_failures() {
        let l = LoginLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 {
            assert!(!l.is_blocked(ip));
            l.record_failure(ip);
        }
        assert!(l.is_blocked(ip));
        assert!(!l.is_blocked(other));
    }

    #[test]
    fn limiter_forgets_after_window() {
        let l = LoginLimiter::new(1, Duration::from_millis(20));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        l.record_failure(ip);
        assert!(l.is_blocked(ip));
        std::thread::sleep(Duration::from_millis(40));
        assert!(!l.is_blocked(ip));
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_bucket() {
        let l = LoginLimiter::new(2, Duration::from_secs(60));
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        l.record_failure(a);
        l.record_failure(b);
        assert!(l.is_blocked(a));
        assert!(l.is_blocked(b));
        assert!(!l.is_blocked(other));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_keyed_as_ipv4() {
        let l = LoginLimiter::new(1, Duration::from_secs(60));
        l.record_failure("::ffff:10.0.0.1".parse().unwrap());
        assert!(l.is_blocked("10.0.0.1".parse().unwrap()));
        assert!(!l.is_blocked("::ffff:10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn global_ceiling_blocks_only_clients_that_failed_too() {
        let l = LoginLimiter::new(5, Duration::from_secs(60));
        for i in 0..GLOBAL_MAX_FAILURES {
            let ip = IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8]);
            assert!(!l.is_blocked(ip));
            l.record_failure(ip);
        }
        assert!(
            !l.is_blocked("192.0.2.1".parse().unwrap()),
            "a clean client is never blocked by other people's failures"
        );
        assert!(l.is_blocked("10.0.0.0".parse().unwrap()));
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        l.record_failure(ip);
        assert!(
            l.is_blocked(ip),
            "one failure is enough once the ceiling is reached"
        );
    }

    #[test]
    fn untracked_addresses_are_blocked_once_the_table_is_full_and_the_ceiling_reached() {
        let l = LoginLimiter::new(5, Duration::from_secs(60));
        for i in 0..MAX_TRACKED_KEYS as u32 {
            l.record_failure(IpAddr::from(i.to_be_bytes()));
        }
        let fresh: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(l.is_blocked(fresh));
        assert!(l.try_reserve(fresh).is_none());
        // Below the tracking limit a fresh address stays free, as before.
        let l = LoginLimiter::new(5, Duration::from_secs(60));
        for i in 0..GLOBAL_MAX_FAILURES as u32 {
            l.record_failure(IpAddr::from(i.to_be_bytes()));
        }
        assert!(!l.is_blocked(fresh));
    }

    #[test]
    fn reservations_count_at_once_and_refunds_give_them_back() {
        let l = LoginLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..3)
            .map(|_| l.try_reserve(ip).expect("allowed"))
            .collect();
        assert!(l.try_reserve(ip).is_none(), "in-flight attempts count");
        for r in held {
            l.refund(r);
        }
        assert!(!l.is_blocked(ip));
        let r = l.try_reserve(ip).unwrap();
        l.refund(r);
        assert_eq!(l.state.lock().unwrap().global.len(), 0);
    }

    #[test]
    fn tracked_keys_are_capped_but_still_count_globally() {
        let l = LoginLimiter::new(1, Duration::from_secs(60));
        for i in 0..MAX_TRACKED_KEYS as u32 + 5 {
            let ip = IpAddr::from(i.to_be_bytes());
            l.record_failure(ip);
        }
        let state = l.state.lock().unwrap();
        assert_eq!(state.per_key.len(), MAX_TRACKED_KEYS);
        assert_eq!(state.global.len(), MAX_TRACKED_KEYS + 5);
    }

    #[test]
    fn replay_guard_allows_first_use_only() {
        let g = ReplayGuard::new();
        let exp = jsonwebtoken::get_current_timestamp() + 60;
        assert!(g.first_use("jti-1", exp));
        assert!(!g.first_use("jti-1", exp));
        assert!(g.first_use("jti-2", exp));
    }

    #[test]
    fn replay_guard_remembers_tokens_through_the_leeway() {
        let g = ReplayGuard::new();
        let just_expired = jsonwebtoken::get_current_timestamp() - 2;
        assert!(g.first_use("late", just_expired));
        assert!(!g.first_use("late", just_expired));
    }

    #[test]
    fn replay_guard_prunes_expired() {
        let g = ReplayGuard::new();
        let past = jsonwebtoken::get_current_timestamp() - 10;
        assert!(g.first_use("old", past));
        g.first_use("trigger-prune", past + 1000);
        assert_eq!(g.len(), 1);
    }
}
