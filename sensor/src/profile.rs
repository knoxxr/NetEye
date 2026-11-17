//! Statistical behaviour profile of one conversation (client -> server, per protocol).
//!
//! While learning, NetEye records how many packets a conversation carries per minute and how far
//! apart its requests are (online mean/variance, Welford). In detection mode it flags:
//!
//! * **Spike**: a minute with far more traffic than learned (scans, floods, write storms).
//! * **Interval change**: the polling cycle moved well away from the learned one (reconfigured or
//!   interposed devices, malfunction).
//! * **Silence**: a regularly polled conversation stopped (device failure, DoS, cabling).
//!
//! All timing uses packet timestamps, so recorded PCAPs and live capture behave the same.

use serde::{Deserialize, Serialize};

pub const WINDOW_MS: i64 = 60_000;
/// Learned minutes needed before volume is judged.
pub const MIN_WINDOWS: u64 = 5;
/// Learned request intervals needed before timing is judged.
pub const MIN_INTERVALS: u64 = 20;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Welford {
    pub n: u64,
    pub mean: f64,
    pub m2: f64,
}

impl Welford {
    pub fn add(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }
    pub fn std(&self) -> f64 {
        if self.n < 2 { 0.0 } else { (self.m2 / (self.n - 1) as f64).sqrt() }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Anomaly {
    Spike { observed: u64, expected: f64 },
    Interval { observed_ms: f64, expected_ms: f64 },
    Silence { silent_ms: i64, expected_ms: f64 },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LinkProfile {
    /// Packets per one-minute window, learned.
    pub volume: Welford,
    /// Milliseconds between consecutive requests, learned.
    pub interval: Welford,
    #[serde(skip)]
    window_start: Option<i64>,
    #[serde(skip)]
    window_count: u64,
    #[serde(skip)]
    window_intervals: (u64, f64),
    #[serde(skip)]
    last_request: Option<i64>,
    #[serde(skip)]
    silence_reported: bool,
}

impl LinkProfile {
    pub fn is_learned(&self) -> bool {
        self.volume.n >= MIN_WINDOWS || self.interval.n >= MIN_INTERVALS
    }

    /// Regular polling: enough samples and a steady cycle (coefficient of variation <= 0.5).
    pub fn is_periodic(&self) -> bool {
        self.interval.n >= MIN_INTERVALS && self.interval.mean > 0.0
            && self.interval.std() <= 0.5 * self.interval.mean
    }

    /// Account one packet; returns anomalies found when a minute closes (detection mode only).
    pub fn observe(&mut self, now: i64, is_request: bool, learning: bool) -> Vec<Anomaly> {
        let mut found = Vec::new();
        let start = *self.window_start.get_or_insert(now);
        if now >= start + WINDOW_MS {
            found.extend(self.close_window(learning));
            let elapsed = (now - start) / WINDOW_MS;
            if learning {
                // Quiet minutes in between are part of normal behaviour too.
                for _ in 1..elapsed.min(60) {
                    self.volume.add(0.0);
                }
            }
            self.window_start = Some(start + elapsed * WINDOW_MS);
            self.window_count = 0;
            self.window_intervals = (0, 0.0);
        }
        self.window_count += 1;
        if is_request {
            if let Some(last) = self.last_request {
                let gap = (now - last) as f64;
                if gap >= 0.0 {
                    if learning {
                        self.interval.add(gap);
                    } else {
                        self.window_intervals.0 += 1;
                        self.window_intervals.1 += gap;
                    }
                }
            }
            self.last_request = Some(now);
            self.silence_reported = false;
        }
        found
    }

    fn close_window(&mut self, learning: bool) -> Vec<Anomaly> {
        let count = self.window_count;
        if learning {
            self.volume.add(count as f64);
            return Vec::new();
        }
        let mut found = Vec::new();
        if self.volume.n >= MIN_WINDOWS {
            let mean = self.volume.mean;
            let spread = self.volume.std().max(mean.sqrt()).max(1.0);
            let c = count as f64;
            if c >= mean + 5.0 * spread && c >= 2.0 * mean + 10.0 {
                found.push(Anomaly::Spike { observed: count, expected: mean });
            }
        }
        let (n, sum) = self.window_intervals;
        if self.interval.n >= MIN_INTERVALS && n >= 5 {
            let observed = sum / n as f64;
            let expected = self.interval.mean;
            let tolerance = (3.0 * self.interval.std()).max(0.5 * expected);
            if (observed - expected).abs() > tolerance {
                found.push(Anomaly::Interval { observed_ms: observed, expected_ms: expected });
            }
        }
        found
    }

    /// A regularly polled conversation that has been quiet far longer than its cycle (once per gap).
    pub fn check_silence(&mut self, now: i64, learning: bool) -> Option<Anomaly> {
        if learning || self.silence_reported || !self.is_periodic() {
            return None;
        }
        let last = self.last_request?;
        let limit = (10.0 * self.interval.mean).max(30_000.0) as i64;
        if now - last > limit {
            self.silence_reported = true;
            return Some(Anomaly::Silence { silent_ms: now - last, expected_ms: self.interval.mean });
        }
        None
    }

    /// Forget everything learned (baseline reset).
    pub fn reset(&mut self) {
        *self = LinkProfile::default();
    }
}

// ------------------------------------------------------------ process points
/// Writes needed before a point is judged.
pub const MIN_POINT_SAMPLES: u64 = 3;
/// Distinct values kept per point; more than this makes the point continuous.
const MAX_STATES: usize = 8;

#[derive(Clone, Debug, PartialEq)]
pub enum PointAnomaly {
    /// Continuous value outside the learned range (plus margin).
    Range { value: f64, min: f64, max: f64 },
    /// State-like point received a value never seen while learning.
    State { value: f64, states: Vec<f64> },
    /// A register/tag that was never written while learning.
    NewPoint { value: f64 },
}

/// What was written to one register/tag/object while learning, and the latest write.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PointProfile {
    pub stats: Welford,
    pub min: f64,
    pub max: f64,
    /// Distinct learned values (up to 8), for state-like points.
    pub states: Vec<f64>,
    pub states_overflow: bool,
    pub discrete: bool,
    pub writes: u64,
    pub last: f64,
    pub last_seen: i64,
    #[serde(skip)]
    reported_new: bool,
    /// Changed since the last flush (engine bookkeeping).
    #[serde(skip)]
    pub dirty: bool,
}

impl PointProfile {
    /// Treated as states: declared discrete, or few integer values learned from enough writes.
    pub fn is_stateful(&self) -> bool {
        self.discrete || (!self.states_overflow && self.states.len() <= 4 && self.stats.n >= 10
            && self.states.iter().all(|v| v.fract() == 0.0))
    }

    /// `measured`: values reported by the device (sensor readings), which drift naturally; they get
    /// a wider margin and are never reported as new points.
    pub fn observe(&mut self, value: f64, discrete: bool, learning: bool, now: i64) -> Option<PointAnomaly> {
        self.observe_kind(value, discrete, learning, now, false)
    }

    pub fn observe_kind(&mut self, value: f64, discrete: bool, learning: bool, now: i64, measured: bool)
                        -> Option<PointAnomaly> {
        self.writes += 1;
        self.last = value;
        self.last_seen = now;
        self.discrete |= discrete;
        if learning {
            if self.stats.n == 0 {
                self.min = value;
                self.max = value;
            }
            self.stats.add(value);
            self.min = self.min.min(value);
            self.max = self.max.max(value);
            if !self.states_overflow && !self.states.contains(&value) {
                if self.states.len() < MAX_STATES {
                    self.states.push(value);
                } else {
                    self.states_overflow = true;
                }
            }
            return None;
        }
        if self.stats.n == 0 {
            if measured || self.reported_new {
                return None;
            }
            self.reported_new = true;
            return Some(PointAnomaly::NewPoint { value });
        }
        if self.stats.n < MIN_POINT_SAMPLES {
            return None;
        }
        if self.is_stateful() {
            if !self.states.contains(&value) {
                return Some(PointAnomaly::State { value, states: self.states.clone() });
            }
            return None;
        }
        // Writes: 10 % of the learned span, so a constant setpoint flags any change.
        // Measurements: 25 % of the span or 3 standard deviations, whichever is wider.
        let span = self.max - self.min;
        let floor = 1e-6 * self.max.abs().max(self.min.abs()).max(1.0);
        let margin = if measured { (0.25 * span).max(3.0 * self.stats.std()).max(floor) }
                     else { (0.1 * span).max(floor) };
        if value < self.min - margin || value > self.max + margin {
            return Some(PointAnomaly::Range { value, min: self.min, max: self.max });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_values_get_a_wider_margin_and_no_new_point_alerts() {
        let mut temp = PointProfile::default();
        for v in [60.0, 62.0, 64.0, 66.0, 68.0, 70.0] {
            temp.observe_kind(v, false, true, 0, true);
        }
        assert!(temp.observe_kind(72.0, false, false, 1, true).is_none(), "drift inside 25 %");
        assert!(matches!(temp.observe_kind(95.0, false, false, 1, true), Some(PointAnomaly::Range { .. })));
        let mut unseen = PointProfile::default();
        assert!(unseen.observe_kind(5.0, false, false, 1, true).is_none());
    }

    #[test]
    fn point_range_states_and_new_points() {
        // Setpoint written between 1200 and 1500 while learning.
        let mut p = PointProfile::default();
        for v in [1200.0, 1350.0, 1500.0, 1420.0, 1300.0] {
            assert!(p.observe(v, false, true, 0).is_none());
        }
        assert!(p.observe(1520.0, false, false, 1).is_none(), "inside the 10 % margin");
        assert_eq!(p.observe(3500.0, false, false, 2), Some(PointAnomaly::Range { value: 3500.0, min: 1200.0, max: 1500.0 }));
        assert!(matches!(p.observe(900.0, false, false, 3), Some(PointAnomaly::Range { .. })));
        assert_eq!(p.last, 900.0);

        // A constant setpoint flags any change.
        let mut constant = PointProfile::default();
        for _ in 0..5 {
            constant.observe(50.0, false, true, 0);
        }
        assert!(constant.observe(50.0, false, false, 1).is_none());
        assert!(matches!(constant.observe(50.5, false, false, 1), Some(PointAnomaly::Range { .. })));

        // Coil only ever switched on while learning: "off" is a new state.
        let mut coil = PointProfile::default();
        for _ in 0..3 {
            coil.observe(1.0, true, true, 0);
        }
        assert!(matches!(coil.observe(0.0, true, false, 1), Some(PointAnomaly::State { .. })));

        // Mode register cycling through 1/2/3: integer states even though not declared discrete.
        let mut mode = PointProfile::default();
        for i in 0..12 {
            mode.observe((i % 3 + 1) as f64, false, true, 0);
        }
        assert!(mode.is_stateful());
        assert!(mode.observe(2.0, false, false, 1).is_none());
        assert!(matches!(mode.observe(7.0, false, false, 1), Some(PointAnomaly::State { .. })));

        // Never written while learning: reported once.
        let mut fresh = PointProfile::default();
        assert_eq!(fresh.observe(1.0, false, false, 1), Some(PointAnomaly::NewPoint { value: 1.0 }));
        assert!(fresh.observe(2.0, false, false, 2).is_none());

        // Too few learned writes: no judgement.
        let mut thin = PointProfile::default();
        thin.observe(10.0, false, true, 0);
        assert!(thin.observe(9999.0, false, false, 1).is_none());
    }

    /// Learn a 1-second polling cycle for ten minutes.
    fn learned() -> (LinkProfile, i64) {
        let mut p = LinkProfile::default();
        let mut t = 0;
        for _ in 0..600 {
            assert!(p.observe(t, true, true).is_empty());
            t += 1000;
        }
        (p, t)
    }

    #[test]
    fn welford_matches_textbook_values() {
        let mut w = Welford::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.add(x);
        }
        assert!((w.mean - 5.0).abs() < 1e-9);
        assert!((w.std() - 2.138).abs() < 1e-3); // sample standard deviation
    }

    #[test]
    fn steady_traffic_raises_nothing() {
        let (mut p, mut t) = learned();
        assert!(p.is_periodic());
        for _ in 0..600 {
            assert!(p.observe(t, true, false).is_empty());
            assert!(p.check_silence(t, false).is_none());
            t += 1000;
        }
    }

    #[test]
    fn spike_interval_change_and_silence() {
        let (mut p, mut t) = learned();
        // Flood: 600 requests within one minute.
        let mut found = Vec::new();
        for _ in 0..600 {
            found.extend(p.observe(t, true, false));
            t += 100;
        }
        found.extend(p.observe(t + WINDOW_MS, true, false));
        assert!(found.iter().any(|a| matches!(a, Anomaly::Spike { .. })), "{found:?}");
        assert!(found.iter().any(|a| matches!(a, Anomaly::Interval { .. })), "100 ms vs learned 1 s");

        // Slowed polling: one request every 4 s, lower volume, so interval only.
        let (mut p, mut t) = learned();
        let mut found = Vec::new();
        for _ in 0..40 {
            found.extend(p.observe(t, true, false));
            t += 4000;
        }
        assert!(found.iter().any(|a| matches!(a, Anomaly::Interval { .. })), "{found:?}");
        assert!(!found.iter().any(|a| matches!(a, Anomaly::Spike { .. })));

        // Silence: reported once after the gap exceeds max(10 cycles, 30 s), re-armed by traffic.
        let (mut p, t) = learned();
        assert!(p.check_silence(t + 20_000, false).is_none());
        assert!(matches!(p.check_silence(t + 31_000, false), Some(Anomaly::Silence { .. })));
        assert!(p.check_silence(t + 60_000, false).is_none(), "reported once per gap");
        p.observe(t + 61_000, true, false);
        assert!(matches!(p.check_silence(t + 100_000, false), Some(Anomaly::Silence { .. })));
    }

    #[test]
    fn learning_never_alerts_and_irregular_links_are_not_silence_checked() {
        let mut p = LinkProfile::default();
        let mut t = 0;
        for i in 0..200 {
            assert!(p.observe(t, true, true).is_empty());
            t += if i % 2 == 0 { 100 } else { 9_000 }; // bursty, not periodic
        }
        assert!(!p.is_periodic());
        assert!(p.check_silence(t + 3_600_000, false).is_none());
        assert!(p.check_silence(t + 3_600_000, true).is_none());
    }

    #[test]
    fn learned_values_round_trip_through_json() {
        let (p, _) = learned();
        let restored: LinkProfile = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(restored.interval, p.interval);
        assert_eq!(restored.volume, p.volume);
    }
}
