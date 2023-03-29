use typed_builder::TypedBuilder;

static counter_manager: CounterManager = Default::default();

struct CounterManager {
    enabled: bool,
    instances: Vec<Counter>,
}

impl CounterManager {
    pub fn print() {
        
    }
}

// Counter is used to collect statistics numbers.
#[derive(TypedBuilder)]
#[builder(build_method(vis="", name=__build))]
struct Counter {
    #[builder(default)]
    name: String,
    #[builder(default, setter(into))]
    value: AtomicUsize,
}

impl Counter {
    pub fn value(&self) -> usize {
        self.value
    }

    pub fn increment(&mut self) {
        self.value += 1;  
    }

    pub fn add(&mut self, other: usize) {
        self.value += other;
    }

    pub fn print(&self) {
        
    }
}

#[allow(non_camel_case_types)]
impl<
    __name: CounterBuilder_Optional<String>,
    __value: CounterBuilder_Optional<usize>,
> CounterBuilder<(__name, __value)> {
    
    pub fn build(self) -> Counter {
        let counter = self.__build();
        
        counter
    }
}