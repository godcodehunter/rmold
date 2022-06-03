use std::env;
use std::collections::{HashSet, HashMap};
use std::sync::atomic::{AtomicU8, AtomicBool};

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

enum CompressKind { 
    COMPRESS_NONE, 
    COMPRESS_GABI, 
    COMPRESS_GNU,
}

enum UnresolvedKind {
    UNRESOLVED_ERROR,
    UNRESOLVED_WARN,
    UNRESOLVED_IGNORE, 
}

enum SeparateCodeKind {
    SEPARATE_LOADABLE_SEGMENTS,
    SEPARATE_CODE,
    NOSEPARATE_CODE,
}

enum CetReportKind {
    CET_REPORT_NONE,
    CET_REPORT_WARNING,
    CET_REPORT_ERROR,
}

enum ShuffleSectionsKind {
    SHUFFLE_SECTIONS_NONE,
    SHUFFLE_SECTIONS_SHUFFLE,
    SHUFFLE_SECTIONS_REVERSE, 
}

struct VersionPattern {
    pattern: &str,
    ver_idx: u16,
    is_cpp: bool,
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

enum BuildIdKind {
    NONE, 
    HEX, 
    HASH, 
    UUID, 
}

struct BuildId {
    kind: BuildIdKind,
    value: Vec<u8>, 
    hash_size: i64,   
}

impl BuildId {
    fn size(&self) -> i64 {
        match self.kind {
            BuildIdKind::NONE => unreachable!(),
            BuildIdKind::HEX => self.value.len(),
            BuildIdKind::HASH => self.hash_size,
            BuildIdKind::UUID => 16,
        }
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

// Command-line arguments
struct Cli {
    build_id: BuildId,
    z_cet_report: CetReportKind,
    compress_debug_sections: CompressKind,
    z_separate_code: SeparateCodeKind,
    shuffle_sections: ShuffleSectionsKind,
    unresolved_symbols: UnresolvedKind,
    Bsymbolic: bool,
    Bsymbolic_functions: bool,
    allow_multiple_definition: bool,
    color_diagnostics: bool,
    default_symver: bool,
    demangle: bool,
    discard_all: bool,
    discard_locals: bool,
    eh_frame_hdr: bool,
    emit_relocs: bool,
    enable_new_dtags: bool,
    export_dynamic: bool,
    fatal_warnings: bool,
    fork: bool,
    gc_sections: bool,
    gdb_index: bool,
    hash_style_gnu: bool,
    hash_style_sysv: bool,
    icf: bool,
    icf_all: bool,
    ignore_data_address_equality: bool,
    is_static: bool,
    lto_pass2: bool,
    noinhibit_exec: bool,
    oformat_binary: bool,
    omagic: bool,
    pack_dyn_relocs_relr: bool,
    perf: bool,
    pic: bool,
    pie: bool,
    print_gc_sections: bool,
    print_icf_sections: bool,
    print_map: bool,
    quick_exit: bool,
    relax: bool,
    relocatable: bool,
    repro: bool,
    rosegment: bool,
    shared: bool,
    stats: bool,
    strip_all: bool,
    strip_debug: bool,
    trace: bool,
    warn_common: bool,
    warn_once: bool,
    warn_textrel: bool,
    z_copyreloc: bool,
    z_defs: bool,
    z_delete: bool,
    z_dlopen: bool,
    z_dump: bool,
    z_execstack: bool,
    z_execstack_if_needed: bool,
    z_ibt: bool,
    z_ibtplt: bool,
    z_initfirst: bool,
    z_interpose: bool,
    z_keep_text_section_prefix: bool,
    z_nodefaultlib: bool,
    z_now: bool,
    z_origin: bool,
    z_relro: bool,
    z_shstk: bool,
    z_text: bool,
    emulation: i64,
    filler: i64,
    print_dependencies: i64,
    spare_dynamic_tags: i64,
    thread_count: i64,
    unique: Option<GlobPattern>,
    shuffle_sections_seed: Option<u64>,
    Map: String,
    chroot: String,
    dependency_file: String,
    directory: String,
    dynamic_linker: String,
    entry: String, 
    fini: String,
    init: String,
    output: String,
    package_metadata: String,
    plugin: String,
    rpaths: String,
    soname: String,
    sysroot: String,
    retain_symbols_file: &HashSet<&str>, 
    section_start: HashMap<&str, u64>, 
    ignore_ir_file: HashSet<&str>, 
    wrap: HashSet<&str>, 
    defsyms: Vec<(Symbol<E>*, std::variant<Symbol<E> *, u64>)>, 
    library_paths: Vec<String>, 
    plugin_opt: Vec<String>, 
    version_definitions: Vec<String>,
    auxiliary: Vec<&str>, 
    exclude_libs: Vec<&str>, 
    filter: Vec<&str>, 
    require_defined: Vec<&str>,
    trace_symbol: Vec<&str>,
    undefined: Vec<&str>, 
    image_base: u64,
}

impl Default for Cli {
    fn default() -> Self {
        Self { 
            build_id: Default::default(), 
            z_cet_report: CET_REPORT_NONE, 
            compress_debug_sections: COMPRESS_NONE, 
            z_separate_code: SEPARATE_LOADABLE_SEGMENTS, 
            shuffle_sections: SHUFFLE_SECTIONS_NONE,  
            unresolved_symbols: UNRESOLVED_ERROR, 
            Bsymbolic: false, 
            Bsymbolic_functions: false, 
            allow_multiple_definition: false, 
            color_diagnostics: false, 
            default_symver: false, 
            demangle: true, 
            discard_all: false, 
            discard_locals: false, 
            eh_frame_hdr: true, 
            emit_relocs: false, 
            enable_new_dtags: true, 
            export_dynamic: false, 
            fatal_warnings: false, 
            fork: true, 
            gc_sections: false, 
            gdb_index: false, 
            hash_style_gnu: false, 
            hash_style_sysv: true, 
            icf: false, 
            icf_all: false, 
            ignore_data_address_equality: false, 
            is_static: false, 
            lto_pass2: false, 
            noinhibit_exec: false,
            oformat_binary: false,
            omagic: false,
            pack_dyn_relocs_relr: false, 
            perf: false, 
            pic: false,
            pie: false,
            print_gc_sections: false, 
            print_icf_sections: false, 
            print_map: false, 
            quick_exit: true, 
            relax: true, 
            relocatable: false, 
            repro: false, 
            rosegment: true, 
            shared: false, 
            stats: false, 
            strip_all: false, 
            strip_debug: false, 
            trace: false, 
            warn_common: false, 
            warn_once: false, 
            warn_textrel: false, 
            z_copyreloc: true, 
            z_defs: false, 
            z_delete: true, 
            z_dlopen: true, 
            z_dump: true, 
            z_execstack: false, 
            z_execstack_if_needed: false, 
            z_ibt: false, 
            z_ibtplt: false, 
            z_initfirst: false, 
            z_interpose: false, 
            z_keep_text_section_prefix: false, 
            z_nodefaultlib: false, 
            z_now: false, 
            z_origin: false, 
            z_relro: true, 
            z_shstk: false, 
            z_text: false, 
            emulation: -1, 
            filler: -1, 
            print_dependencies: 0, 
            spare_dynamic_tags: 5, 
            thread_count: 0, 
            unique: Default::default(), 
            shuffle_sections_seed: Default::default(), 
            Map: Default::default(), 
            chroot: Default::default(), 
            dependency_file: Default::default(), 
            directory: Default::default(), 
            dynamic_linker: Default::default(), 
            entry: "_start", 
            fini:  "_fini",
            output: "a.out",
            package_metadata: ,
            plugin: ,
            rpaths: ,
            soname: ,
            sysroot: ,
            retain_symbols_file: ,
            section_start: ,
            ignore_ir_file: ,
            wrap: ,
            defsyms: ,
            library_paths: ,
            plugin_opt: ,
            version_definitions: ,
            auxiliary: ,
            exclude_libs: ,
            filter: ,
            require_defined: ,
            trace_symbol: ,
            undefined: ,
            image_base: 0x200000,
        }
    }
}

// Context represents a context object for each invocation of the linker.
// It contains command line flags, pointers to singleton objects
// (such as linker-synthesized output sections), unique_ptrs for
// resource management, and other miscellaneous objects.
struct Context<E> {
    args: Cli,
    version_patterns: Vec<VersionPattern>,
    default_version: u16,
    page_size: i64,
    plt_hdr_size: i64,
    plt_size: i64,

    // Reader context
    as_needed: bool,
    whole_archive: bool,
    is_static: bool,
    in_lib: bool,
    file_priority: i64,
    visited: HashSet<&str>, 
    tbb::task_group tg;

    has_error: bool,
    has_lto_object: bool,

    // Symbol table
    tbb::concurrent_hash_map<std::string_view, Symbol<E>, HashCmp> symbol_map;
    tbb::concurrent_hash_map<std::string_view, ComdatGroup, HashCmp> comdat_groups;
    tbb::concurrent_vector<std::unique_ptr<MergedSection<E>>> merged_sections;
    tbb::concurrent_vector<std::unique_ptr<Chunk<E>>> output_chunks;
    std::vector<std::unique_ptr<OutputSection<E>>> output_sections;
    obj_cache: FileCache<E, ObjectFile<E>>,
    dso_cache: FileCache<E, SharedFile<E>>,

    tbb::concurrent_vector<std::unique_ptr<TimerRecord>> timer_records;
    tbb::concurrent_vector<std::function<void()>> on_exit;

    tbb::concurrent_vector<std::unique_ptr<ObjectFile<E>>> obj_pool;
    tbb::concurrent_vector<std::unique_ptr<SharedFile<E>>> dso_pool;
    tbb::concurrent_vector<std::unique_ptr<u8[]>> string_pool;
    tbb::concurrent_vector<std::unique_ptr<MappedFile<Context<E>>>> mf_pool;
    tbb::concurrent_vector<std::vector<ElfRel<E>>> rel_pool;

    // Symbol auxiliary data
    symbol_aux: Vec<SymbolAux>,

    // Fully-expanded command line args
    cmdline_args: Vec<&str>,

    // Input files
    std::vector<ObjectFile<E> *> objs;
    std::vector<SharedFile<E> *> dsos;
    ObjectFile<E> *internal_obj = nullptr;

    // Output buffer
    std::unique_ptr<OutputFile<Context<E>>> output_file;
    buf: *const u8,
    overwrite_output_file: bool,
    
    chunks: Vec<*const Chunk<E>>,
    needs_tlsld: AtomicBool,
    has_gottp_rel: AtomicBool,
    has_textrel: AtomicBool,

    // For --warn-once
    tbb::concurrent_hash_map<void *, int> warned;

    // Output chunks
    ehdr: *const OutputEhdr<E>,
    shdr: *const OutputShdr<E>,
    phdr: *const OutputPhdr<E>,
    interp: *const InterpSection<E>,
    got: *const GotSection<E>,
    gotplt: *const GotPltSection<E>,
    relplt: *const RelPltSection<E>,
    reldyn: *const RelDynSection<E>,
    relrdyn: *const RelrDynSection<E>,
    dynamic: *const DynamicSection<E>,
    strtab: *const StrtabSection<E>,
    dynstr: *const DynstrSection<E>,
    hash: *const HashSection<E>,
    gnu_hash: *const GnuHashSection<E>,
    shstrtab: *const ShstrtabSection<E>,
    plt: *const PltSection<E>,
    pltgot: *const PltGotSection<E>,
    symtab: *const SymtabSection<E>,
    dynsym: *const DynsymSection<E>,
    eh_frame: *const EhFrameSection<E>,
    eh_frame_hdr: *const EhFrameHdrSection<E>,
    copyrel: *const CopyrelSection<E>,
    copyrel_relro: *const CopyrelSection<E>,
    versym: *const VersymSection<E>,
    verneed: *const VerneedSection<E>,
    verdef: *const VerdefSection<E>,
    buildid: *const BuildIdSection<E>,
    note_package: *const NotePackageSection<E>,
    note_property: *const NotePropertySection<E>,
    gdb_index: *const GdbIndexSection,
    thumb_to_arm: *const ThumbToArmSection,
    tls_trampoline: *const TlsTrampolineSection,

    // For --gdb-index
    debug_info: *const Chunk<E>,
    debug_abbrev: *const Chunk<E>,
    debug_ranges: *const Chunk<E>,
    debug_addr: *const Chunk<E>,
    debug_rnglists: *const Chunk<E>,

    // For --relocatable
    r_chunks: Vec<RChunk<E> *>;
    r_ehdr: *const ROutputEhdr<E>,
    r_shdr: *const ROutputShdr<E>,
    r_shstrtab: *const RStrtabSection<E>,
    r_strtab: *const RStrtabSection<E>,
    r_symtab: *const RSymtabSection<E>,

    tls_begin: u64,
    tls_end: u64,
    relax_tlsdesc: bool,

    // Linker-synthesized symbols
    _DYNAMIC: *const Symbol<E>,
    _GLOBAL_OFFSET_TABLE_: *const Symbol<E>,
    _TLS_MODULE_BASE_: *const Symbol<E>,
    __GNU_EH_FRAME_HDR: *const Symbol<E>,
    __bss_start: *const Symbol<E>, 
    __ehdr_start: *const Symbol<E>,
    __executable_start: *const Symbol<E>, 
    __exidx_end: *const Symbol<E>,
    __exidx_start: *const Symbol<E>,
    __fini_array_end: *const Symbol<E>,
    __fini_array_start: *const Symbol<E>,
    __global_pointer: *const Symbol<E>,
    __init_array_end: *const Symbol<E>,
    __init_array_start: *const Symbol<E>,
    __preinit_array_end: *const Symbol<E>,
    __preinit_array_start: *const Symbol<E>,
    __rel_iplt_end: *const Symbol<E>,
    __rel_iplt_start: *const Symbol<E>,
    _edata: *const Symbol<E>,
    _end: *const Symbol<E>,
    _etext: *const Symbol<E>,
    edata: *const Symbol<E>, 
    end: *const Symbol<E>, 
    etext: *const Symbol<E>, 
}

impl Default for Context<E> {
    fn default() -> Self {
        Self { 
            args: ,
            default_version: VER_NDX_GLOBAL,
            page_size: -1,
            plt_hdr_size: -1,
            plt_size: -1,
            as_needed: false,
            whole_archive: false,
            is_static: ,
            in_lib: false,
            file_priority: 10000,
            visited: ,
            tg: ,
            has_error: false,
            has_lto_object: false, 
            symbol_map: ,
            comdat_groups: ,
            merged_sections: ,
            output_chunks: ,
            output_sections: ,
            obj_cache: ,
            dso_cache: ,
            timer_records: ,
            on_exit: ,
            obj_pool: ,
            dso_pool: ,
            string_pool: ,
            mf_pool: ,
            rel_pool: ,
            symbol_aux: ,
            cmdline_args: ,
            objs: ,
            dsos: ,
            internal_obj: ,
            output_file: ,
            buf: std::ptr::null(),
            overwrite_output_file: true,
            chunks: Default::default(),
            needs_tlsld: false,
            has_gottp_rel: false,
            has_textrel: false,
            warned: ,
            ehdr: std::ptr::null(),
            shdr: std::ptr::null(),
            phdr: std::ptr::null(),
            interp: std::ptr::null(),
            got: std::ptr::null(),
            gotplt: std::ptr::null(),
            relplt: std::ptr::null(),
            reldyn: std::ptr::null(),
            relrdyn: std::ptr::null(),
            dynamic: std::ptr::null(),
            strtab: std::ptr::null(),
            dynstr: std::ptr::null(),
            hash: std::ptr::null(),
            gnu_hash: std::ptr::null(),
            shstrtab: std::ptr::null(),
            plt: std::ptr::null(),
            pltgot: std::ptr::null(),
            symtab: std::ptr::null(),
            dynsym: std::ptr::null(),
            eh_frame: std::ptr::null(),
            eh_frame_hdr: std::ptr::null(),
            copyrel: std::ptr::null(),
            copyrel_relro: std::ptr::null(),
            versym: std::ptr::null(),
            verneed: std::ptr::null(),
            verdef: std::ptr::null(),
            buildid: std::ptr::null(),
            note_package: std::ptr::null(),
            note_property: std::ptr::null(),
            gdb_index: std::ptr::null(),
            thumb_to_arm: std::ptr::null(),
            tls_trampoline: std::ptr::null(),
            debug_info: std::ptr::null(),
            debug_abbrev: std::ptr::null(),
            debug_ranges: std::ptr::null(),
            debug_addr: std::ptr::null(),
            debug_rnglists: std::ptr::null(),
            r_chunks: std::ptr::null(),
            r_ehdr: std::ptr::null(),
            r_shdr: std::ptr::null(),
            r_shstrtab: std::ptr::null(),
            r_strtab: std::ptr::null(),
            r_symtab: std::ptr::null(),
            tls_begin: 0,
            tls_end: 0,
            relax_tlsdesc: false,
            _DYNAMIC: std::ptr::null(),
            _GLOBAL_OFFSET_TABLE_: std::ptr::null(),
            _TLS_MODULE_BASE_: std::ptr::null(),
            __GNU_EH_FRAME_HDR: std::ptr::null(),
            __bss_start: std::ptr::null(),
            __ehdr_start: std::ptr::null(),
            __executable_start: std::ptr::null(),
            __exidx_end: std::ptr::null(),
            __exidx_start: std::ptr::null(),
            __fini_array_end: std::ptr::null(),
            __fini_array_start: std::ptr::null(),
            __global_pointer: std::ptr::null(),
            __init_array_end: std::ptr::null(),
            __init_array_start: std::ptr::null(),
            __preinit_array_end: std::ptr::null(),
            __preinit_array_start: std::ptr::null(),
            __rel_iplt_end: std::ptr::null(),
            __rel_iplt_start: std::ptr::null(),
            _edata: std::ptr::null(),
            _end: std::ptr::null(),
            _etext: std::ptr::null(),
            edata: std::ptr::null(),
            end: std::ptr::null(),
            etext: std::ptr::null(),
        }
    }
}

impl Context<E> {
    fn new() {

    }

    fn checkpoint() {
        
    }

    fn open_library(&self) {

    }

    fn find_library(&self) {

    }

    fn read_file() {

    }
}

// Symbol represents a defined symbol.
//
// A symbol has not only one but several different addresses if it
// has PLT or GOT entries. This class provides various functions to
// compute different addresses.
struct Symbol<E> {
    // A symbol is owned by a file. If two or more files define the
    // same symbol, the one with the strongest definition owns the symbol.
    // If `file` is null, the symbol is equivalent to nonexistent.
    file: *mut InputFile<E>,

    value: u64,

    const char *nameptr = nullptr;
    namelen: i32,

    // Index into the symbol table of the owner file.
    sym_idx: i32,

    // shndx > 0  : symbol is in file's shndx'th section
    // shndx == 0 : absolute symbol
    // shndx < 0  : symbol is in the -shndx'th output section
    shndx: i32,

    aux_idx: i32,
    ver_idx: u16,

    // `flags` has NEEDS_ flags.
    flags: AtomicU8,

    tbb::spin_mutex mu;
    visibility: AtomicU8,

    is_weak: bool,
    write_to_symtab: bool, // for --strip-all and the like
    traced: bool,          // for --trace-symbol
    wrap: bool,             // for --wrap

    // If a symbol can be resolved to a symbol in a different ELF file at
    // runtime, `is_imported` is true. If a symbol is a dynamic symbol and
    // can be used by other ELF file at runtime, `is_exported` is true.
    //
    // Note that both can be true at the same time. Such symbol represents
    // a function or data exported from this ELF file which can be
    // imported by other definition at runtime. That is actually a usual
    // exported symbol when creating a DSO. In other words, a dynamic
    // symbol exported by a DSO is usually imported by itself.
    //
    // If is_imported is true and is_exported is false, it is a dynamic
    // symbol just imported from other DSO.
    //
    // If is_imported is false and is_exported is true, there are two
    // possible cases. If we are creating an executable, we know that
    // exported symbols cannot be intercepted by any DSO (because the
    // dynamic loader searches a dynamic symbol from an executable before
    // examining any DSOs), so any exported symbol is export-only in an
    // executable. If we are creating a DSO, export-only symbols
    // represent a protected symbol (i.e. a symbol whose visibility is
    // STV_PROTECTED).
    is_imported: bool, 
    is_exported: bool, 

    // `is_canonical` is true if this symbol represents a "canonical" PLT.
    // Here is the explanation as to what is the canonical PLT is.
    //
    // In C/C++, the process-wide function pointer equality is guaratneed.
    // That is, if you take an address of a function `foo`, it's always
    // evaluated to the same address wherever you do that.
    //
    // For the sake of explanation, assume that `libx.so` exports a
    // function symbol `foo`, and there's a program that uses `libx.so`.
    // Both `libx.so` and the main executable take the address of `foo`,
    // which must be evaluated to the same address because of the above
    // guarantee.
    //
    // If the main executable is position-independent code (PIC), `foo` is
    // evaluated to the beginning of the function code, as you would have
    // expected. The address of `foo` is stored to GOTs, and the machine
    // code that takes the address of `foo` reads the GOT entries at
    // runtime.
    //
    // However, if it's not PIC, the main executable's code was compiled
    // to not use GOT (note that shared objects are always PIC, only
    // executables can be non-PIC). It instead assumes that `foo` (and any
    // other global variables/functions) has an address that is fixed at
    // link-time. This assumption is correct if `foo` is in the same
    // position-dependent executable, but it's not if `foo` is imported
    // from some other DSO at runtime.
    //
    // In this case, we use the address of the `foo`'s PLT entry in the
    // main executable (whose address is fixed at link-time) as its
    // address. In order to guarantee pointer equality, we also need to
    // fill foo's GOT entries in DSOs with the addres of the foo's PLT
    // entry instead of `foo`'s real address. We can do that by setting a
    // symbol value to `foo`'s dynamic symbol. If a symbol value is set,
    // the dynamic loader initialize `foo`'s GOT entries with that value
    // instead of the symbol's real address.
    //
    // We call such PLT entry in the main executable as "canonical".
    // If `foo` has a canonical PLT, its address is evaluated to its
    // canonical PLT's address. Otherwise, it's evaluated to `foo`'s
    // address.
    //
    // Only non-PIC main executables may have canonical PLTs. PIC
    // executables and shared objects never have a canonical PLT.
    //
    // This bit manages if we need to make this symbol's PLT canonical.
    // This bit is meaningful only when the symbol has a PLT entry.
    is_canonical: bool, 

    // If an input object file is not compiled with -fPIC (or with
    // -fno-PIC), the file not position independent. That means the
    // machine code included in the object file does not use GOT to access
    // global variables. Instead, it assumes that addresses of global
    // variables are known at link-time.
    //
    // Let's say `libx.so` exports a global variable `foo`, and a main
    // executable uses the variable. If the executable is not compiled
    // with -fPIC, we can't simply apply a relocation that refers `foo`
    // because `foo`'s address is not known at link-time.
    //
    // In this case, we could print out the "recompile with -fPIC" error
    // message, but there's a way to workaround.
    //
    // The loader supports a feature so-called "copy relocations".
    // A copy relocation instructs the loader to copy data from a DSO to a
    // specified location in the main executable. By using this feature,
    // you can make `foo`'s data to a BSS region at runtime. With that,
    // you can apply relocations agianst `foo` as if `foo` existed in the
    // main executable's BSS area, whose address is known at link-time.
    //
    // Copy relocations are used only by position-dependent executables.
    // Position-independent executables and DSOs don't need them because
    // they use GOT to access global variables.
    //
    // `has_copyrel` is true if we need to emit a copy relocation for this
    // symbol. If the original symbol in a DSO is in a read-only memory
    // region, `copyrel_readonly` is set to true so that the copied data
    // will become read-only at run-time.
    has_copyrel: bool, 
    copyrel_readonly: bool, 

    // For LTO. True if the symbol is referenced by a regular object (as
    // opposed to IR object).
    referenced_by_regular_obj: bool, 

    // Target-dependent extra members.
    extra: SymbolExtras<E>,
}

impl Default for Symbol<E> {
    fn default() -> Self {
        Self { 
            file: std::ptr::null,
            value: 0,
            namelen: 0,
            sym_idx: -1,
            shndx: 0,
            aux_idx: -1,
            ver_idx: 0,
            flags: 0,
            mu: ,
            visibility: STV_DEFAULT,
            is_weak: false,
            write_to_symtab: false,
            traced: false,
            wrap: false,
            is_imported: false,
            is_exported: false,
            is_canonical: false,
            has_copyrel: false,
            copyrel_readonly: false,
            referenced_by_regular_obj: false,
            extra: Default::default(),
        }
    }
}

impl<E> Symbol<E> {
    fn get_addr(&self, ctx: Context<E>, allow_plt: bool) -> u64 {
        if self.file && self.file.is_dso {
            SectionFragmentRef<E> &sf_ref = ((ObjectFile<E> *)file)->sym_fragments[sym_idx];
            
            if sf_ref.frag {
                if !sf_ref.frag.is_alive {
                    // This condition is met if a non-alloc section refers an
                    // alloc section and if the referenced piece of data is
                    // garbage-collected. Typically, this condition occurs if a
                    // debug info section refers a string constant in .rodata.
                    return 0;
                }

                return sf_ref.frag.get_addr(ctx) + sf_ref.addend;
            }
        }

        if self.has_copyrel {
            return if self.copyrel_readonly {
                ctx.copyrel_relro.shdr.sh_addr + self.value
            } else {
                ctx.copyrel.shdr.sh_addr + self.value
            };
        }

        if allow_plt && self.has_plt(ctx) {
            if self.is_imported || self.esym().st_type == STT_GNU_IFUNC {
                return self.get_plt_addr(ctx);
            }
        }

        let isec = self.get_input_section();
        if isec {
            if !isec.is_alive {
                if isec.killed_by_icf {
                    return isec.leader.get_addr() + self.value;
                }

                if isec.name() == ".eh_frame" {

                }

                // The control can reach here if there's a relocation that refers
                // a local symbol belonging to a comdat group section. This is a
                // violation of the spec, as all relocations should use only global
                // symbols of comdat members. However, .eh_frame tends to have such
                // relocations.
                return 0;
            }

            return isec.get_addr() + self.value;
        }

        return self.value;
    }

    fn get_got_addr(&self, &ctx: Context<E>) -> u64 {
        ctx.got.shdr.sh_addr + self.get_got_idx(ctx) * E::word_size
    }
    
    fn get_gotplt_addr(&self, &ctx: Context<E>) -> u64 {
        assert!(self.get_gotplt_idx(ctx) != -1);
        ctx.gotplt.shdr.sh_addr + self.get_gotplt_idx(ctx) * E::word_size
    }
    
    fn get_gottp_addr(&self, &ctx: Context<E>) -> u64 {
        assert!(self.get_gottp_idx(ctx) != -1);
        ctx.got.shdr.sh_addr + self.get_gottp_idx(ctx) * E::word_size
    }
    
    fn get_tlsgd_addr(&self, &ctx: Context<E>) -> u64 {
        assert!(self.get_tlsgd_idx(ctx) != -1);
        ctx.got.shdr.sh_addr + self.get_tlsgd_idx(ctx) * E::word_size
    }
    
    fn get_tlsdesc_addr(&self, &ctx: Context<E>) -> u64 {
        assert!(self.get_tlsdesc_idx(ctx) != -1);
        ctx.got.shdr.sh_addr + self.get_tlsdesc_idx(ctx) * E::word_size
    }

    fn get_plt_addr(&self, &ctx: Context<E>) -> u64 {
        let idx = self.get_plt_idx(ctx);
        if idx != -1 {
            return ctx.plt.shdr.sh_addr + ctx.plt_hdr_size + idx * ctx.plt_size;
        }

        ctx.pltgot.shdr.sh_addr + self.get_pltgot_idx(ctx) * E::pltgot_size
    }

    fn set_got_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].got_idx < 0);
        ctx.symbol_aux[self.aux_idx].got_idx = idx;
    }
    
    fn set_gotplt_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].gotplt_idx < 0);
        ctx.symbol_aux[self.aux_idx].gotplt_idx = idx;
    }
    
    fn set_gottp_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].gottp_idx < 0);
        ctx.symbol_aux[self.aux_idx].gottp_idx = idx;
    }
    
    fn set_tlsgd_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].tlsgd_idx < 0);
        ctx.symbol_aux[self.aux_idx].tlsgd_idx = idx;
    }
    
    fn set_tlsdesc_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].tlsdesc_idx < 0);
        ctx.symbol_aux[self.aux_idx].tlsdesc_idx = idx;
    }
    
    fn set_plt_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].plt_idx < 0);
        ctx.symbol_aux[self.aux_idx].plt_idx = idx;
    }
    
    fn set_pltgot_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].pltgot_idx < 0);
        ctx.symbol_aux[self.aux_idx].pltgot_idx = idx;
    }
    
    fn set_dynsym_idx(&self, &ctx: Context<E>, idx: i32) {
        assert!(self.aux_idx != -1);
        assert!(ctx.symbol_aux[self.aux_idx].dynsym_idx < 0);
        ctx.symbol_aux[self.aux_idx].dynsym_idx = idx;
    }

    fn get_got_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1
        } else {
            ctx.symbol_aux[self.aux_idx].got_idx
        }
    }
    
    fn get_gotplt_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1 
        } else {
            ctx.symbol_aux[self.aux_idx].gotplt_idx
        }
    }
    
    fn get_gottp_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1
        } else {
            ctx.symbol_aux[self.aux_idx].gottp_idx
        }
    }
    
    fn get_tlsgd_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1   
        } else {
            ctx.symbol_aux[self.aux_idx].tlsgd_idx
        }
    }
    
    fn get_tlsdesc_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1
        } else {
            ctx.symbol_aux[self.aux_idx].tlsdesc_idx
        }
    }
    
    fn get_plt_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1
        } else {
            ctx.symbol_aux[self.aux_idx].plt_idx
        }
    }
    
    fn get_pltgot_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1
        } else {
            ctx.symbol_aux[self.aux_idx].pltgot_idx
        }
    }

    fn get_dynsym_idx(&self, &ctx: Context<E>) -> i32 {
        if self.aux_idx == -1 {
            -1
        } else {
            ctx.symbol_aux[self.aux_idx].dynsym_idx
        }
    }

    fn has_plt(&self, &ctx: Context<E>) -> bool {
        self.get_plt_idx(ctx) != -1 || self.get_pltgot_idx(ctx) != -1
    }
    
    fn has_got(&self, &ctx: Context<E>) -> bool {
        self.get_got_idx(ctx) != -1
    }

    fn is_absolute(&self) -> bool { 
        if self.file.is_dso {
            return self.esym().is_abs();
        }

        !self.is_imported && !self.get_frag() && self.shndx == 0
    }
    
    fn is_relative(&self) { 
        !self.is_absolute()
    }

    fn get_input_section(&self) -> *const InputSection<E> {
        if self.shndx > 0 {
            assert!(!self.file.is_dso);
            return ((ObjectFile<E> *)file)->sections[shndx].get();
          }
          return std::ptr::null();
    }
    
    fn get_type(&self) -> u32 {
        if self.esym().st_type == STT_GNU_IFUNC && self.file.is_dso {
            return STT_FUNC;
        }
       
        self.esym().st_type
    }
    
    fn get_version(&self) -> Option<> {
        if self.file.is_dso {
            return ((SharedFile<E> *)file)->version_strings[ver_idx];
        }

        return "";
    }
    
    fn esym(&self) -> ElfSym<E> {
        self.file.elf_sym[self.sym_idx]
    }
    
    fn get_frag(&self) -> *const SectionFragment<E> {
        if !self.file || self.file.is_dso {
            return std::ptr::null();
        }
        
        return ((ObjectFile<E> *)file)->sym_fragments[sym_idx].frag;
    }
    
    fn name() {

    }
}

mod macho {
    pub fn main() {
        Context::<E> ctx;

        
    }
} 

mod elf {
    fn new_object_file(ctx: &Context<E>, mf: *const MappedFile<Context<E>>, archive_name: String) {

    }

    fn new_lto_obj() {

    }

    fn new_shared_file() {

    }

    fn read_file(&ctx: Context<E>, mf: *const MappedFile<Context<E>>) {
        if (ctx.visited.contains(mf->name))
            return;

        
    }

    fn get_machine_type() {

    }

    fn deduce_machine_type() {

    }

    fn open_library() {

    }

    fn find_library() {

    }

    fn read_input_files() {

    }

    fn get_mtime() {

    }

    fn reload_input_files() {

    }

    fn show_stats() {

    }

    fn elf_main() {
        Context<E> ctx;

        
    }

    pub fn main() {

    }
}

fn main() {
    let cmd = env::current_exe().unwrap().file_name().unwrap();

    if cmd == "ld64" || cmd == "ld64.mold" {
        return macho::main();
    }

    return elf::main();
}
