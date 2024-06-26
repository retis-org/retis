use std::ops;

use chrono::{DateTime, Utc};

use crate::event_type;

/// Representation of `struct timespec` to hold time values.
#[event_type]
#[derive(Copy, Default)]
pub struct TimeSpec {
    sec: i64,
    nsec: i64,
}

impl TimeSpec {
    const NSECS_IN_SEC: i64 = 1000000000;

    pub fn new(mut sec: i64, mut nsec: i64) -> Self {
        if nsec >= Self::NSECS_IN_SEC {
            let diff = nsec / Self::NSECS_IN_SEC;
            sec += diff;
            nsec -= diff * Self::NSECS_IN_SEC;
        }

        Self { sec, nsec }
    }

    pub fn sec(&self) -> i64 {
        self.sec
    }

    pub fn nsec(&self) -> i64 {
        self.nsec
    }
}

impl ops::Add for TimeSpec {
    type Output = TimeSpec;

    fn add(self, rhs: Self) -> Self {
        let mut sec = self.sec + rhs.sec;
        let mut nsec = self.nsec + rhs.nsec;

        if nsec >= Self::NSECS_IN_SEC {
            sec += 1;
            nsec -= Self::NSECS_IN_SEC;
        }

        Self { sec, nsec }
    }
}

impl ops::Sub for TimeSpec {
    type Output = TimeSpec;

    fn sub(self, rhs: Self) -> Self {
        let mut sec = self.sec - rhs.sec;
        let mut nsec = self.nsec - rhs.nsec;

        if nsec < 0 {
            sec -= 1;
            nsec += Self::NSECS_IN_SEC;
        }

        Self { sec, nsec }
    }
}

impl From<TimeSpec> for DateTime<Utc> {
    fn from(val: TimeSpec) -> DateTime<Utc> {
        DateTime::from_timestamp(val.sec(), val.nsec() as u32)
            .expect("Could not convert TimeSpec to DateTime")
    }
}

#[cfg(test)]
mod tests {
    use super::TimeSpec;

    #[test]
    fn timespec_new() {
        let ts = TimeSpec::new(42, 100001);
        assert_eq!(ts.sec(), 42);
        assert_eq!(ts.nsec(), 100001);

        let ts = TimeSpec::new(42, TimeSpec::NSECS_IN_SEC + 1);
        assert_eq!(ts.sec(), 43);
        assert_eq!(ts.nsec(), 1);

        let ts = TimeSpec::new(42, TimeSpec::NSECS_IN_SEC * 10 + 1);
        assert_eq!(ts.sec(), 52);
        assert_eq!(ts.nsec(), 1);
    }

    #[test]
    fn timespec_add() {
        let ts = TimeSpec::new(42, 100001);

        let tmp = ts + TimeSpec::new(1, 30);
        assert_eq!(tmp.sec(), 43);
        assert_eq!(tmp.nsec(), 100031);

        let tmp = ts + TimeSpec::new(0, TimeSpec::NSECS_IN_SEC - 1);
        assert_eq!(tmp.sec(), 43);
        assert_eq!(tmp.nsec(), 100000);
    }

    #[test]
    fn timespec_sub() {
        let ts = TimeSpec::new(42, 100001);

        let tmp = ts - TimeSpec::new(1, 30);
        assert_eq!(tmp.sec(), 41);
        assert_eq!(tmp.nsec(), 99971);

        let tmp = ts - TimeSpec::new(0, 100002);
        assert_eq!(tmp.sec(), 41);
        assert_eq!(tmp.nsec(), TimeSpec::NSECS_IN_SEC - 1);

        let tmp = ts - TimeSpec::new(42, 100002);
        assert_eq!(tmp.sec(), -1);
        assert_eq!(tmp.nsec(), TimeSpec::NSECS_IN_SEC - 1);
    }
}
