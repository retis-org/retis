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
