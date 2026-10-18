//! Abuse limits: failed sign-in attempts per address, per wider block and overall, and one-time
//! codes.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Rejections across all clients within one window that reach the global ceiling; what happens
/// then is the limiter's [`Ceiling`]. Only settled rejections count here; checks still in flight
/// do not, so a busy server never trips it by itself.
pub const GLOBAL_MAX_FAILURES: usize = 30;
/// Attempts (rejected or in flight) one wider block, an IPv6 /48 or IPv4 /24, may have in a
/// window, so one allocation cannot spread over thousands of addresses.
pub const BLOCK_MAX_ATTEMPTS: usize = 25;
/// Addresses, and separately blocks, tracked at once.
const MAX_TRACKED: usize = 10_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Counted while its check runs; dropped again unless it is rejected.
    Pending,
    Failure,
}

#[derive(Default)]
struct Bucket {
    attempts: Vec<(Instant, Kind)>,
}

impl Bucket {
    fn prune(&mut self, now: Instant, window: Duration) {
        self.attempts
            .retain(|(t, _)| now.duration_since(*t) < window);
    }

    fn has_failure(&self) -> bool {
        self.attempts.iter().any(|(_, k)| *k == Kind::Failure)
    }

    fn take(&mut self, at: Instant) -> bool {
        match self
            .attempts
            .iter()
            .rposition(|(t, k)| *t == at && *k == Kind::Pending)
        {
            Some(i) => {
                self.attempts.remove(i);
                true
            }
            None => false,
        }
    }
}

/// What happens once rejections across all clients reach [`GLOBAL_MAX_FAILURES`] in a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ceiling {
    /// Every client is refused until the window passes, the owner too. Right for one shared
    /// secret, such as the owner's password, where a single right guess gives everything away:
    /// the total guessing rate stays bounded however many addresses an attacker has.
    BlockEveryone,
    /// Only clients with a rejection of their own in the window are refused, so other people's
    /// failures never lock out someone who has not failed. When so many addresses are tracked
    /// that the table is full, an untracked address is judged by its block, and refused as
    /// [`Refusal::Busy`] when that is untracked too. Right when each person signs in with their
    /// own credential.
    BlockFailing,
}

/// Why an attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// This client, or its block, has too many rejected or concurrent attempts.
    TooMany,
    /// So many addresses are failing that new, untracked ones cannot be told apart: the server
    /// is under attack and refuses them until it calms down.
    Busy,
}

/// Limits credential attempts per client address (IPv4 address, IPv6 /64) and per wider block
/// (IPv4 /24, IPv6 /48), plus a ceiling on rejections across all clients.
pub struct LoginLimiter {
    max: usize,
    window: Duration,
    ceiling: Ceiling,
    state: Mutex<LimiterState>,
}

struct LimiterState {
    addresses: HashMap<IpAddr, Bucket>,
    blocks: HashMap<IpAddr, Bucket>,
    failures: VecDeque<Instant>,
    last_sweep: Instant,
}

/// The client an address belongs to: the address itself for IPv4, its /64 for IPv6.
fn address_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// The wider block an address belongs to: its IPv4 /24 or IPv6 /48.
fn block_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
    }
}

impl LimiterState {
    fn prune(&mut self, now: Instant, window: Duration) {
        while self
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
            self.failures.pop_front();
        }
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        for map in [&mut self.addresses, &mut self.blocks] {
            map.retain(|_, b| {
                b.prune(now, window);
                !b.attempts.is_empty()
            });
        }
    }
}

fn push(map: &mut HashMap<IpAddr, Bucket>, key: IpAddr, at: Instant, kind: Kind) -> Option<IpAddr> {
    if map.len() >= MAX_TRACKED && !map.contains_key(&key) {
        return None;
    }
    map.entry(key).or_default().attempts.push((at, kind));
    Some(key)
}

impl LoginLimiter {
    /// At most `max` attempts per address and [`BLOCK_MAX_ATTEMPTS`] per block within `window`,
    /// and `ceiling` once rejections across all addresses reach [`GLOBAL_MAX_FAILURES`].
    pub fn new(max: usize, window: Duration, ceiling: Ceiling) -> Self {
        Self {
            max,
            window,
            ceiling,
            state: Mutex::new(LimiterState {
                addresses: HashMap::new(),
                blocks: HashMap::new(),
                failures: VecDeque::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Whether a new attempt from `ip` would be refused.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.refusal(ip).is_some()
    }

    /// Why a new attempt from `ip` would be refused, if it would.
    pub fn refusal(&self, ip: IpAddr) -> Option<Refusal> {
        let mut state = self.state.lock().expect("limiter lock");
        self.blocked(&mut state, ip, Instant::now())
    }

    fn blocked(&self, state: &mut LimiterState, ip: IpAddr, now: Instant) -> Option<Refusal> {
        state.prune(now, self.window);
        let window = self.window;
        let ceiling = state.failures.len() >= GLOBAL_MAX_FAILURES;
        if ceiling && self.ceiling == Ceiling::BlockEveryone {
            return Some(Refusal::TooMany);
        }
        let LimiterState {
            addresses, blocks, ..
        } = state;
        let addresses_full = addresses.len() >= MAX_TRACKED;
        let blocks_full = blocks.len() >= MAX_TRACKED;
        let block = blocks.get_mut(&block_key(ip)).map(|b| {
            b.prune(now, window);
            &*b
        });
        if block.is_some_and(|b| b.attempts.len() >= BLOCK_MAX_ATTEMPTS) {
            return Some(Refusal::TooMany);
        }
        match addresses.get_mut(&address_key(ip)) {
            Some(b) => {
                b.prune(now, window);
                if b.attempts.len() >= self.max || (ceiling && b.has_failure()) {
                    return Some(Refusal::TooMany);
                }
            }
            // Untracked because the table is full: judge the address by its block instead.
            None if addresses_full => match block {
                Some(b) if ceiling && b.has_failure() => return Some(Refusal::TooMany),
                None if blocks_full && ceiling => return Some(Refusal::Busy),
                _ => {}
            },
            None => {}
        }
        None
    }

    /// Records a rejected attempt from `ip` that was not reserved first.
    pub fn record_failure(&self, ip: IpAddr) {
        let mut state = self.state.lock().expect("limiter lock");
        let now = Instant::now();
        state.prune(now, self.window);
        state.failures.push_back(now);
        push(&mut state.addresses, address_key(ip), now, Kind::Failure);
        push(&mut state.blocks, block_key(ip), now, Kind::Failure);
    }

    /// Counts an attempt before it is checked, so concurrent attempts share the per-client and
    /// per-block limits. Settle it with [`Self::fail`] if the credential is rejected, otherwise
    /// with [`Self::refund`]. Until then it does not count toward the global ceiling.
    pub fn try_reserve(&self, ip: IpAddr) -> Result<Reservation, Refusal> {
        let mut state = self.state.lock().expect("limiter lock");
        let now = Instant::now();
        if let Some(refusal) = self.blocked(&mut state, ip, now) {
            return Err(refusal);
        }
        let address = push(&mut state.addresses, address_key(ip), now, Kind::Pending);
        let block = push(&mut state.blocks, block_key(ip), now, Kind::Pending);
        Ok(Reservation {
            address,
            block,
            at: now,
        })
    }

    /// Gives a reserved attempt back: it was accepted, or could not be checked.
    pub fn refund(&self, reservation: Reservation) {
        let mut state = self.state.lock().expect("limiter lock");
        Self::take(&mut state, &reservation);
    }

    /// Keeps a reserved attempt as a rejection, counted toward the global ceiling too.
    pub fn fail(&self, reservation: Reservation) {
        let mut state = self.state.lock().expect("limiter lock");
        let now = Instant::now();
        Self::take(&mut state, &reservation);
        state.failures.push_back(now);
        if let Some(k) = reservation.address {
            state
                .addresses
                .entry(k)
                .or_default()
                .attempts
                .push((reservation.at, Kind::Failure));
        }
        if let Some(k) = reservation.block {
            state
                .blocks
                .entry(k)
                .or_default()
                .attempts
                .push((reservation.at, Kind::Failure));
        }
    }

    fn take(state: &mut LimiterState, r: &Reservation) {
        if let Some(b) = r.address.and_then(|k| state.addresses.get_mut(&k)) {
            b.take(r.at);
        }
        if let Some(b) = r.block.and_then(|k| state.blocks.get_mut(&k)) {
            b.take(r.at);
        }
    }
}

/// An attempt counted by [`LoginLimiter::try_reserve`] until it is settled.
#[derive(Debug)]
#[must_use = "settle the reservation with fail or refund"]
pub struct Reservation {
    address: Option<IpAddr>,
    block: Option<IpAddr>,
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
        let l = LoginLimiter::new(3, Duration::from_secs(60), Ceiling::BlockFailing);
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
        let l = LoginLimiter::new(1, Duration::from_millis(20), Ceiling::BlockFailing);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        l.record_failure(ip);
        assert!(l.is_blocked(ip));
        std::thread::sleep(Duration::from_millis(40));
        assert!(!l.is_blocked(ip));
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_bucket() {
        let l = LoginLimiter::new(2, Duration::from_secs(60), Ceiling::BlockFailing);
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
        let l = LoginLimiter::new(1, Duration::from_secs(60), Ceiling::BlockFailing);
        l.record_failure("::ffff:10.0.0.1".parse().unwrap());
        assert!(l.is_blocked("10.0.0.1".parse().unwrap()));
        assert!(!l.is_blocked("::ffff:10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn global_ceiling_blocks_only_clients_that_failed_too() {
        let l = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockFailing);
        for i in 0..GLOBAL_MAX_FAILURES {
            let ip = IpAddr::from([10, (i / 20) as u8, (i % 20) as u8, 1]);
            assert!(!l.is_blocked(ip));
            l.record_failure(ip);
        }
        assert!(
            !l.is_blocked("192.0.2.1".parse().unwrap()),
            "a clean client is never blocked by other people's failures"
        );
        assert!(l.is_blocked("10.0.0.1".parse().unwrap()));
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        l.record_failure(ip);
        assert!(
            l.is_blocked(ip),
            "one failure is enough once the ceiling is reached"
        );
    }

    #[test]
    fn a_shared_secret_ceiling_blocks_everyone_until_the_window_passes() {
        let l = LoginLimiter::new(5, Duration::from_millis(200), Ceiling::BlockEveryone);
        for i in 0..GLOBAL_MAX_FAILURES {
            l.record_failure(IpAddr::from([10, (i / 20) as u8, (i % 20) as u8, 1]));
        }
        let clean: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(l.is_blocked(clean), "the owner waits too");
        assert_eq!(l.try_reserve(clean).unwrap_err(), Refusal::TooMany);
        std::thread::sleep(Duration::from_millis(250));
        assert!(!l.is_blocked(clean));
    }

    #[test]
    fn checks_in_flight_never_count_toward_the_ceiling() {
        let l = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockFailing);
        let held: Vec<_> = (0..40u8)
            .map(|i| l.try_reserve(IpAddr::from([10, i, 0, 1])).expect("allowed"))
            .collect();
        assert_eq!(l.state.lock().unwrap().failures.len(), 0);
        let failed: IpAddr = "192.0.2.3".parse().unwrap();
        l.record_failure(failed);
        assert!(
            !l.is_blocked(failed),
            "40 checks in flight are not 30 rejections"
        );
        for r in held {
            l.refund(r);
        }
    }

    #[test]
    fn a_rejected_reservation_becomes_a_failure() {
        let l = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockFailing);
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let r = l.try_reserve(ip).unwrap();
        l.fail(r);
        let state = l.state.lock().unwrap();
        assert_eq!(state.failures.len(), 1);
        assert!(state.addresses[&address_key(ip)].has_failure());
        assert_eq!(state.addresses[&address_key(ip)].attempts.len(), 1);
    }

    #[test]
    fn one_wider_block_cannot_spread_over_many_addresses() {
        let l = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockFailing);
        for i in 0..BLOCK_MAX_ATTEMPTS as u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, i, 0, 0, 0, 1));
            let _ = l.try_reserve(ip).expect("each /64 tries once");
        }
        let same_block = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 999, 0, 0, 0, 1));
        assert_eq!(l.try_reserve(same_block).unwrap_err(), Refusal::TooMany);
        let other_block = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1));
        assert!(l.try_reserve(other_block).is_ok());
        let v4: Vec<_> = (0..BLOCK_MAX_ATTEMPTS as u8)
            .map(|i| l.try_reserve(IpAddr::from([198, 51, 100, i])).unwrap())
            .collect();
        assert_eq!(
            l.try_reserve("198.51.100.250".parse().unwrap())
                .unwrap_err(),
            Refusal::TooMany,
            "an IPv4 /24 is one block"
        );
        for r in v4 {
            l.refund(r);
        }
    }

    #[test]
    fn a_full_table_judges_new_addresses_by_their_block() {
        let l = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockFailing);
        // 10,000 failing addresses in 40 /24s fill the address table and reach the ceiling.
        for i in 0..MAX_TRACKED as u32 {
            l.record_failure(IpAddr::from(i.to_be_bytes()));
        }
        assert!(
            !l.is_blocked("203.0.113.7".parse().unwrap()),
            "a new address in a clean block still gets in"
        );
        assert_eq!(
            l.refusal("0.0.39.200".parse().unwrap()),
            Some(Refusal::TooMany),
            "a new address in a failing block does not"
        );
        // 10,000 failing blocks fill the block table too: new blocks can't be told apart.
        let l = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockFailing);
        for i in 0..MAX_TRACKED as u32 {
            l.record_failure(IpAddr::from((i << 8).to_be_bytes()));
        }
        assert_eq!(
            l.refusal("203.0.113.7".parse().unwrap()),
            Some(Refusal::Busy)
        );
    }

    #[test]
    fn reservations_count_at_once_and_refunds_give_them_back() {
        let l = LoginLimiter::new(3, Duration::from_secs(60), Ceiling::BlockFailing);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..3)
            .map(|_| l.try_reserve(ip).expect("allowed"))
            .collect();
        assert_eq!(
            l.try_reserve(ip).unwrap_err(),
            Refusal::TooMany,
            "in-flight attempts count"
        );
        for r in held {
            l.refund(r);
        }
        assert!(!l.is_blocked(ip));
        let r = l.try_reserve(ip).unwrap();
        l.refund(r);
        let state = l.state.lock().unwrap();
        assert!(state.addresses.values().all(|b| b.attempts.is_empty()));
        assert!(state.failures.is_empty());
    }

    #[test]
    fn tracked_addresses_are_capped_but_still_count_globally() {
        let l = LoginLimiter::new(1, Duration::from_secs(60), Ceiling::BlockFailing);
        for i in 0..MAX_TRACKED as u32 + 5 {
            let ip = IpAddr::from(i.to_be_bytes());
            l.record_failure(ip);
        }
        let state = l.state.lock().unwrap();
        assert_eq!(state.addresses.len(), MAX_TRACKED);
        assert_eq!(state.failures.len(), MAX_TRACKED + 5);
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
