// This file implements HyperLogLog algorithm, which estimates
// the number of unique items in a given multiset.
//
// For more info, read
// https://engineering.fb.com/2018/12/13/data-infrastructure/hyperloglog

struct HyperLogLog {
    buckets: Vec<>,
}

impl HyperLogLog {
    const NBUCKETS: i64 = 2048;
    const ALPHA: f64 = 0.79402;

    fn new() -> Self {
        Self { buckets: }
    }

    fn insert(hash: u32) {
        todo!()
    }

    fn get_cardinality(&self) -> i64 {
        self.buckets
    }  

    fn merge(other: &HyperLogLog) {
        todo!()
    }  
}
