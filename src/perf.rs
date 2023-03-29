use std::sync::atomic::{ AtomicUsize, Ordering};
use typed_builder::TypedBuilder;

pub struct Stats {
    enabled: bool,
    instances: Vec<Counter>,
}

impl Stats {
    pub fn counters() {

    }
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

impl Counter {
    pub fn value(&self) -> usize {
        self.value.load(Ordering::Relaxed)
    }

    pub fn inc(&mut self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&mut self, other: usize) {
        self.value.fetch_add(other, Ordering::Relaxed);
    }
}

#[allow(non_camel_case_types)]
impl<
        __name: CounterBuilder_Optional<String>,
        __description: CounterBuilder_Optional<String>,
        __value: CounterBuilder_Optional<AtomicUsize>,
    > CounterBuilder<(__name, __description, __value)>
{
    pub fn build(self) -> Counter {
        let counter = self.__build();

        counter
    }
}