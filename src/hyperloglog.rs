#![feature(core_intrinsics)]
use static_assertions::const_assert;
use std::{
    intrinsics::powif64,
    sync::atomic::{AtomicU8, Ordering},
};

fn assign_if(atomic: &AtomicU8, new: u8, mut cmp: impl FnMut(u8, u8) -> bool) {
    let mut old = atomic.load(Ordering::Relaxed);
    while cmp(old, new) {
        match atomic.compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => old = current,
        }
    }
}

fn assign_if_gt(atomic: &AtomicU8, new: u8) {
    assign_if(atomic, new, |old, new| old < new)
}

fn assign_if_ls(atomic: &AtomicU8, new: u8) {
    assign_if(atomic, new, |old, new| old > new)
}

// This file implements HyperLogLog algorithm, which estimates
// the number of unique items in a given multiset.
//
// For more info, read
// https://engineering.fb.com/2018/12/13/data-infrastructure/hyperloglog

pub struct HyperLogLog<const NBUCKETS: usize> {
    buckets: [AtomicU8; NBUCKETS],
}

// TODO: now we can't use impl associative const as const generic parameters for Self
// TODO: do some with type now we have many conversion
const NBUCKETS: usize = 2048;

impl HyperLogLog<NBUCKETS> {
    const ALPHA: f64 = 0.79402;

    fn new() -> Self {
        Self {
            buckets: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
        }
    }

    fn insert(&mut self, hash: u32) {
        const_assert!(NBUCKETS - 1 <= u32::MAX as usize);

        let new = hash.leading_zeros() as u8 + 1;
        let index = (hash & (NBUCKETS - 1) as u32) as usize;
        assign_if_gt(&self.buckets[index], new);
    }

    fn get_cardinality(&self) -> i64 {
        let z = self
            .buckets
            .iter()
            .fold(0, |acc, item| { 
                let item = item.load(Ordering::Relaxed) as u32;
                acc + 1/i32::pow(2, item)
            } );

        // TODO: bad code all conversion
        Self::ALPHA as i64 * NBUCKETS as i64 * NBUCKETS as i64  / z as i64
    }

    fn merge(&mut self, other: &Self) {
        for i in 0..NBUCKETS {
            let new = other.buckets[i].load(Ordering::Relaxed);
            assign_if_gt(&self.buckets[i], new);
        }
    }
}