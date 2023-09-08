use std::sync::atomic::{AtomicU8, Ordering};

// This file implements HyperLogLog algorithm, which estimates
// the number of unique items in a given multiset.
//
// For more info, read
// https://engineering.fb.com/2018/12/13/data-infrastructure/hyperloglog
const NBUCKETS: usize = 2048;

pub struct HyperLogLog {
    buckets: [AtomicU8; NBUCKETS],
}

impl HyperLogLog {
    const ALPHA: f64 = 0.79402;

    fn new() -> Self {
        Self {
            buckets: [0; NBUCKETS],
        }
    }

    fn insert(&mut self, hash: u32) {
        let new = hash.leading_zeros() as u8 + 1;
        let index = (hash & (NBUCKETS - 1) as u32) as usize;
        self.buckets[index].fetch_max(new, Ordering::Relaxed);
    }

    fn get_cardinality(&self) -> i64 {
        let z = self.buckets.iter().fold(0, |acc, item| {
            let item = item.load(Ordering::Relaxed) as u32;
            acc + 1 / i32::pow(2, item)
        });

        // TODO: bad code all conversion
        Self::ALPHA as i64 * NBUCKETS as i64 * NBUCKETS as i64 / z as i64
    }

    fn merge(&mut self, other: &Self) {
        for i in 0..NBUCKETS {
            let new: u8 = other.buckets[i].load(Ordering::Relaxed);
            self.buckets[i].fetch_max(new, Ordering::Relaxed);
        }
    }
}
