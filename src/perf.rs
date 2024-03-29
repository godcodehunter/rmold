#![feature(option_get_or_insert_default)]

use std::{
    collections::HashMap,
    panic::Location,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
use typed_builder::TypedBuilder;

static COUNTERS: Mutex<Option<HashMap<String, &'static AtomicUsize>>> = Mutex::new(None);
static COUNTERS_META: Mutex<Option<HashMap<String, CounterMeta>>> = Mutex::new(None);

pub fn counters() -> Vec<Counter> {
    let mut counter_guard = COUNTERS.lock().unwrap();
    let counter_map = counter_guard.get_or_insert_default();

    let mut meta_guard = COUNTERS_META.lock().unwrap();
    let meta_map = meta_guard.get_or_insert_default();

    counter_map
        .into_iter()
        .map(|(key, value)| -> Counter {
            let meta = &meta_map[key];

            Counter {
                name: meta.name.clone(),
                description: meta.description.clone(),
                value: AtomicUsize::new(value.load(Ordering::Relaxed)),
            }
        })
        .collect::<Vec<_>>()
}

struct CounterMeta {
    name: String,
    description: String,
}

// Counter is used to collect statistics numbers.
#[derive(TypedBuilder)]
#[builder(build_method(vis="", name=__build))]
pub struct Counter {
    #[builder(default, setter(into))]
    name: String,
    #[builder(default, setter(into))]
    description: String,
    #[builder(default, setter(into))]
    value: AtomicUsize,
}

#[allow(non_camel_case_types)]
impl<
        __name: ::typed_builder::Optional<String>,
        __description: ::typed_builder::Optional<String>,
        __value: ::typed_builder::Optional<AtomicUsize>,
    > CounterBuilder<(__name, __description, __value)>
{
    #[track_caller]
    pub fn build(self) -> &'static AtomicUsize {
        let mut counter_guard = COUNTERS.lock().unwrap();
        let counter_map = counter_guard.get_or_insert_default();

        let mut meta_guard = COUNTERS_META.lock().unwrap();
        let meta_map = meta_guard.get_or_insert_default();

        let counter = self.__build();
        let location = Location::caller();
        let key = format!(
            "{}:{}:{}",
            location.file(),
            location.line(),
            location.column(),
        );

        meta_map.entry(key.clone()).or_insert(CounterMeta {
            name: counter.name,
            description: counter.description,
        });

        counter_map.entry(key).or_insert({
            let item = Box::new(counter.value);
            Box::leak(item)
        })
    }
}



pub struct Timer {
    name: String,
    record: TimerRecord,
}

impl Timer {
    pub fn new(name: &str, parent: Option<&Timer>) -> Self {
        
    }

    pub fn stop() {

    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.record.stop()
    }
}
