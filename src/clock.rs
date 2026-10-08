//! A `Clock` abstraction so tests can control time instead of sleeping.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Something that can report the current time.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// A `Clock` backed by the real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A `Clock` with a fixed, manually advanced time, for tests.
#[derive(Debug)]
pub struct TestClock {
    now: Mutex<SystemTime>,
}

impl TestClock {
    pub fn new(start: SystemTime) -> Self {
        TestClock {
            now: Mutex::new(start),
        }
    }

    /// Moves the clock forward by `d`.
    pub fn advance(&self, d: Duration) {
        let mut now = self.now.lock().expect("TestClock mutex poisoned");
        *now += d;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().expect("TestClock mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_advances() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let clock = TestClock::new(start);
        assert_eq!(clock.now(), start);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
    }

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        let a = clock.now();
        let b = clock.now();
        assert!(b >= a);
    }
}
