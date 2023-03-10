use std::env;
use std::collections::{HashSet, HashMap};
use std::sync::atomic::{AtomicU8, AtomicBool};

mod filetype;
mod mold;
mod elf;

static SHA256_SIZE: i32 = 32;

// Mergeable section fragments
struct SectionFragment<E> {
    output_section: &MergedSection<E>,
    offset: u32,
    p2align: AtomicU8,
    is_alive: AtomicBool,
}

impl<E> Default for SectionFragment<E> {
    fn default() -> Self {
        Self { 
            output_section: Default::default(),
            offset: -1,
            p2align: 0,
            is_alive: false,
        }
    }
}

impl<E> SectionFragment<E> {
    fn get_addr(&self, &ctx: Context<E>) -> u64 {
        self.output_section.shdr.sh_addr + self.offset
    }
}

// Chunk represents a contiguous region in an output file.
struct Chunk {
    name: &str,
    shdr: ElfShdr<E>,
    shndx: i64,
    extra_addralign: i64,
}

impl Default for Chunk {
    fn default() -> Self {
        Self { 
            name: Default::default(),
            shdr: Default::default(),
            shndx: 0,
            extra_addralign: 1,
        }
    }
}

impl Chunk {
    fn kind() {}
    fn copy_buf() {}
    fn write_to() {}
    fn update_shdr() {}
    fn get_uncompressed_data() {}
}

struct MergedSection<E> { 
    estimator: HyperLogLog,
    map: ConcurrentMap<SectionFragment<E>>,
    shard_offsets: Vec<i64>,
    once_flag: std::once_flag,
}

impl MergedSection {
    fn new(name: &str, flags: u64, ty: u32) -> Self {
        Self { 
            estimator: (), 
            map: (), 
            shard_offsets: (), 
            once_flag: (),
        }
    }
    
    fn get_instance(&ctx: Context<E>, name: &str, ty: u64, flags: u64) -> *const MergedSection<E> {
        name = get_output_name(ctx, name);
        flags = flags & ~(u64)SHF_GROUP & ~(u64)SHF_MERGE & ~(u64)SHF_STRINGS &
          ~(u64)SHF_COMPRESSED;

        auto find = [&]() -> MergedSection * {
        for (std::unique_ptr<MergedSection<E>> &osec : ctx.merged_sections)
            if (std::tuple(name, flags, type) ==
                std::tuple(osec->name, osec->shdr.sh_flags, osec->shdr.sh_type))
            return osec.get();
        return nullptr;
        };
    
        // Search for an exiting output section.
        static std::shared_mutex mu;
        {
        std::shared_lock lock(mu);
        if (MergedSection *osec = find())
            return osec;
        }
    
        // Create a new output section.
        std::unique_lock lock(mu);
        if (MergedSection *osec = find())
        return osec;
    
        MergedSection *osec = new MergedSection(name, flags, type);
        ctx.merged_sections.emplace_back(osec);
        return osec;
    }
    
    fn insert(data: &str, hash: u64, p2align: i64) -> *const SectionFragment<E> {
        // TODO 
        
        let frag: *const SectionFragment<E>;
        let inserted: bool;
        // TODO 
        assert!(frag);
        
        update_maximum(frag.p2align, p2align);
        frag
    }
    
    fn assign_offsets(&self, &ctx: Context<E>) {
        let sizes = Vec::<i64>::with_capacity(self.map.NUM_SHARDS);
        let max_p2aligns = Vec::<i64>::with_capacity(self.map.NUM_SHARDS);
        self.shard_offsets.resize(self.map.NUM_SHARDS + 1);

        let shard_size: i64 = map.nbuckets / map.NUM_SHARDS;

        let p2align: i64 = 0;

    }
    
    fn copy_buf(&self, &ctx: Context<E>) {
        
    }
    
    fn write_to(&ctx: Context<E>, buff: *const u8) {
        let shard_size: i64 = map.nbuckets / map.NUM_SHARDS;


    }
    
    fn print_stats(&self, &ctx: Context<E>) {
        let used: i64 = 0;

        for i in 0..self.map.nbuckets {
            if self.map.keys[i] {
                used += 1;
            }
        }

        SyncOut(ctx); 
    }
}

struct FileCache {

}

impl FileCache {
    fn store() {

    }

    fn get() {

    }

    fn get_one() {

    }
}

struct InputSection<E> {

}

struct InputFile<E> {
    MappedFile<Context<E>> *mf = nullptr;
    std::span<ElfShdr<E>> elf_sections;
    std::span<ElfSym<E>> elf_syms;
    std::vector<Symbol<E> *> symbols;
    i64 first_global = 0;

    std::string filename;
    is_dso: bool, //= false;
    u32 priority;
    std::atomic_bool is_alive = false;
    std::string_view shstrtab;

    // To create an output .symtab
    u64 local_symtab_idx = 0;
    u64 global_symtab_idx = 0;
    u64 num_local_symtab = 0;
    u64 num_global_symtab = 0;
    u64 strtab_offset = 0;
    u64 strtab_size = 0;

    // For --emit-relocs
    std::vector<i32> output_sym_indices;

    protected:
    std::unique_ptr<Symbol<E>[]> local_syms;
}

mod mmold {
    use crate::mold;

    pub fn get_mold_version() -> &'static str {
        if mold::mold_git_hash.is_empty() {
            return concat!(env!("MOLD_PRODUCT_NAME"), " ", env!("MOLD_VERSION"), " (compatible with GNU ld)");
        }
        concat!(env!("MOLD_PRODUCT_NAME"), " ", env!("MOLD_VERSION"), " (", mmold::mold_git_hash, "; compatible with GNU ld)")
    }

    fn cleanup() {
        todo!()
    }

    std::string errno_string() {
    }

    fn get_self_path() {

    }

    fn vectored_handler() {
        todo!()
    }

    fn install_signal_handler() {
        todo!()
    }

    fn sighandler() {
        todo!()
    }

    fn install_signal_handler() {
        todo!()
    }

    pub fn get_default_thread_count() -> i64 {
        // mold doesn't scale well above 32 threads.
        const n = todo!();
        std::cmp::min(n, 32)
    }
} 

fn main() {
    mold::mold_version = mmold::get_mold_version();
    mold::mold_product_name = env!("MOLD_PRODUCT_NAME");
    let cmd = env::current_exe().unwrap().file_name().unwrap();

    if cmd == "ld64" || cmd == "ld64.mold" {
        return macho::main();
    }

    return elf::main();
}
