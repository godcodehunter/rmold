use std::{collections::{HashSet, HashMap}, path::Path};
use crate::hyperloglog;

use super::elf::MachineType;

pub enum ChunkKind { HEADER, OUTPUT_SECTION, SYNTHETIC }

/// Chunk represents a contiguous region in an output file.
struct Chunk {

}

/// Mergeable section fragments
struct SectionFragment {

}

struct MergedSection {
    estimator: hyperloglog::HyperLogLog, 
    map: HashMap<SectionFragment>,
    shard_offsets: Vec<i64>,
    once_flag: ,
}

impl MergedSection {
    fn get_instance() {

    }

    fn insert() {

    }

    fn assign_offsets() {

    }
    
    fn copy_buf() {

    }

    fn write_to() {
        
    }

    // TODO: use concurent map version  
    pub fn print_stats(&self) {
        let used = self.map.len();
        let free = self.map.capacity();

        println!(
            "name={} estimation={}, actual={}", 
            self.name, 
            free, 
            used
        );
    }
}

/// InputFile is the base class of ObjectFile and SharedFile.
struct InputFile<E> {
// public:
//   InputFile(Context<E> &ctx, MappedFile<Context<E>> *mf);
//   InputFile() : filename("<internal>") {}

//   virtual ~InputFile() = default;

//   template<typename T> std::span<T>
//   get_data(Context<E> &ctx, const ElfShdr<E> &shdr);

//   template<typename T> std::span<T>
//   get_data(Context<E> &ctx, i64 idx);

//   std::string_view get_string(Context<E> &ctx, const ElfShdr<E> &shdr);
//   std::string_view get_string(Context<E> &ctx, i64 idx);

//   ElfEhdr<E> &get_ehdr() { return *(ElfEhdr<E> *)mf->data; }
//   ElfPhdr<E> *get_phdr() { return (ElfPhdr<E> *)(mf->data + get_ehdr().e_phoff); }

//   ElfShdr<E> *find_section(i64 type);

//   virtual void resolve_symbols(Context<E> &ctx) = 0;
//   void clear_symbols();

//   virtual void
//   mark_live_objects(Context<E> &ctx,
//                     std::function<void(InputFile<E> *)> feeder) = 0;

//   std::span<Symbol<E> *> get_global_syms();
//   std::string_view get_source_name() const;

//   MappedFile<Context<E>> *mf = nullptr;
//   std::span<ElfShdr<E>> elf_sections;
//   std::span<ElfSym<E>> elf_syms;
    pub symbols: Vec<&Symbol<E>>,
    pub first_global: i64, //= 0;

//   std::string filename;
//   bool is_dso = false;
//   u32 priority;
//   std::atomic_bool is_alive = false;
//   std::string_view shstrtab;
//   std::string_view symbol_strtab;

  // To create an output .symtab
  pub local_symtab_idx: u64, //= 0;
  pub global_symtab_idx: u64, //= 0;
  pub num_local_symtab: u64, //= 0;
  pub num_global_symtab: u64, //= 0;
  pub strtab_offset: u64, //= 0;
  pub strtab_size: u64, //= 0;

  // For --emit-relocs
  pub output_sym_indices: Vec<i32>,

  local_syms: Vec<Symbol<E>>,
  frag_syms: Vec<Symbol<E>>,
}

// InputSection represents a section in an input object file.
struct InputSection<E> {
    pub file: &ObjectFile<E>,
    // For COMDAT de-duplication and garbage collection
    pub is_alive: AtomicBool,
}

impl<E> InputSection<E> {
    pub fn uncompress() {}
    pub fn uncompress_to() {}
    pub fn scan_relocations() {}
    pub fn write_to() {}
    pub fn apply_reloc_alloc() {}
    pub fn apply_reloc_nonalloc() {}
    pub fn kil() {}

    pub fn name() {}
    pub fn get_priority() {}
    pub fn get_addr() {}
    pub fn get_addend() {}
    pub fn shder() {}
}

// A comdat section typically represents an inline function,
// which are de-duplicated by the linker.
//
// For each inline function, there's one comdat section, which
// contains section indices of the function code and its data such as
// string literals, if any.
//
// Comdat sections are identified by its signature. If two comdat
// sections have the same signature, the linker picks up one and
// discards the other by eliminating all sections that the other
// comdat section refers to.
struct ComdatGroup {
    // The file priority of the owner file of this comdat section.

}

// ObjectFile represents an input .o file.
// class ObjectFile : public InputFile<E> {
// public:
#[derive(Default)]
struct ObjectFile<E> {
    pub parent: InputFile<E>,

  static ObjectFile<E> *create(Context<E> &ctx, MappedFile<Context<E>> *mf,
                               std::string archive_name, bool is_in_lib);

  void parse(Context<E> &ctx);
  void initialize_mergeable_sections(Context<E> &ctx);
  void register_section_pieces(Context<E> &ctx);
  void resolve_symbols(Context<E> &ctx) override;
  void mark_live_objects(Context<E> &ctx,
                         std::function<void(InputFile<E> *)> feeder) override;
  void convert_undefined_weak_symbols(Context<E> &ctx);
  void resolve_comdat_groups();
  void mark_addrsig(Context<E> &ctx);
  void eliminate_duplicate_comdat_groups();
  void claim_unresolved_symbols(Context<E> &ctx);
  void scan_relocations(Context<E> &ctx);
  void convert_common_symbols(Context<E> &ctx);
  void compute_symtab_size(Context<E> &ctx);
  void populate_symtab(Context<E> &ctx);

  i64 get_shndx(const ElfSym<E> &esym);
  InputSection<E> *get_section(const ElfSym<E> &esym);

  std::string archive_name;
  // TODO: std::vector<std::unique_ptr<InputSection<E>>> sections;
  pub sections: Vec<InputSection<E>>,

  std::vector<std::unique_ptr<MergeableSection<E>>> mergeable_sections;
  bool is_in_lib = false;
  std::vector<ElfShdr<E>> elf_sections2;
  pub cies: Vec<CieRecord<E>>;
  pub fde: Vec<FdeRecord<E>>;
  std::vector<const char *> symvers;
//   std::vector<std::pair<ComdatGroup *, std::span<U32<E>>> > comdat_groups;
  pub comdat_groups: Vec<(ComdatGroup, )>,
  bool exclude_libs = false;
  std::vector<std::pair<u32, u32>> gnu_properties;
  bool is_lto_obj = false;
  bool needs_executable_stack = false;

  u64 num_dynrel = 0;
  u64 reldyn_offset = 0;

  u64 fde_idx = 0;
  u64 fde_offset = 0;
  u64 fde_size = 0;

  // For ICF
  std::unique_ptr<InputSection<E>> llvm_addrsig;
  // For .gdb_index
  InputSection<E> *debug_info = nullptr;
  InputSection<E> *debug_ranges = nullptr;
  InputSection<E> *debug_rnglists = nullptr;
  InputSection<E> *debug_pubnames = nullptr;
  InputSection<E> *debug_pubtypes = nullptr;
  std::vector<std::string_view> compunits;
  std::vector<GdbIndexName> gdb_names;
  i64 compunits_idx = 0;
  i64 attrs_size = 0;
  i64 attrs_offset = 0;
  i64 names_size = 0;
  i64 names_offset = 0;
  i64 num_areas = 0;
  i64 area_offset = 0;

private:
  ObjectFile(Context<E> &ctx, MappedFile<Context<E>> *mf,
             std::string archive_name, bool is_in_lib);

  void initialize_sections(Context<E> &ctx);
  void initialize_symbols(Context<E> &ctx);
  void sort_relocations(Context<E> &ctx);
  void initialize_ehframe_sections(Context<E> &ctx);
  void read_note_gnu_property(Context <E> &ctx, const ElfShdr <E> &shdr, std::vector<std::pair<u32, u32>> &out);
  void read_ehframe(Context<E> &ctx, InputSection<E> &isec);
  void override_symbol(Context<E> &ctx, Symbol<E> &sym,
                       const ElfSym<E> &esym, i64 symidx);
  void merge_visibility(Context<E> &ctx, Symbol<E> &sym, u8 visibility);

  bool has_common_symbol = false;

  const ElfShdr<E> *symtab_sec;
  std::span<U32<E>> symtab_shndx_sec;
};

impl ObjectFile {

}

// Symbol represents a defined symbol.
//
// A symbol has not only one but several different addresses if it
// has PLT or GOT entries. This class provides various functions to
// compute different addresses.
pub struct Symbol<E> {
    // A symbol is owned by a file. If two or more files define the
    // same symbol, the one with the strongest definition owns the symbol.
    // If `file` is null, the symbol is equivalent to nonexistent.
    pub file: *mut InputFile<E>,

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

    pub fn get_input_section(&self) -> Option<&InputSection<E>> {
        if self.shndx > 0 {
            assert!(!self.file.is_dso);
            return ((ObjectFile<E> *)file)->sections[shndx].get();
          }
          return std::ptr::null();
    }
    
    pub fn get_type(&self) -> u32 {
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

enum CetReportKind {
    CET_REPORT_NONE,
    CET_REPORT_WARNING,
    CET_REPORT_ERROR,
}

enum CompressKind { 
    COMPRESS_NONE, 
    COMPRESS_GABI, 
    COMPRESS_GNU,
}

enum SeparateCodeKind {
    SEPARATE_LOADABLE_SEGMENTS,
    SEPARATE_CODE,
    NOSEPARATE_CODE,
}

enum ShuffleSectionsKind {
    SHUFFLE_SECTIONS_NONE,
    SHUFFLE_SECTIONS_SHUFFLE,
    SHUFFLE_SECTIONS_REVERSE, 
}

enum UnresolvedKind {
    UNRESOLVED_ERROR,
    UNRESOLVED_WARN,
    UNRESOLVED_IGNORE, 
}

enum ElementKind {
    STRING, 
    STAR, 
    QUESTION, 
    BRACKET,
}

struct Element {
    kind: GlobKind,
    str: String,
    bitset: ,
}

struct Glob {
    elements: Vec<Element>,
}

impl Glob {
    fn compile(target: &str) -> Option<Self> {

    }

    fn do_match(target: &str, elements: &[Element]) -> bool {
        
    }
}

// TODO
enum SectionOrderKind {
    NONE, 
    SECTION, 
    GROUP, 
    ADDR, 
    ALIGN, 
    SYMBOL,
}

struct SectionOrder {
    kind: SectionOrderKind,
    name: String,
    value: u64,
}

// TODO
enum Def {
    First(&Symbol<>),
    Second(u64),
}

/// Command-line arguments
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
    apply_dynamic_relocs: bool,
    discard_locals: bool,
    eh_frame_hdr: bool,
    emit_relocs: bool,
    enable_new_dtags: bool,
    execute_only: bool,
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
    pub perf: bool,
    pic: bool,
    pie: bool,
    print_gc_sections: bool,
    print_icf_sections: bool,
    pub print_map: bool,
    pub quick_exit: bool,
    relax: bool,
    relocatable: bool,
    repro: bool,
    rosegment: bool,
    shared: bool,
    start_stop: bool,
    pub stats: bool,
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
    z_initfirst: bool,
    z_interpose: bool,
    z_keep_text_section_prefix: bool,
    z_nodefaultlib: bool,
    z_now: bool,
    z_origin: bool,
    z_relro: bool,
    z_shstk: bool,
    z_text: bool,
    pub emulation: MachineType,
    filler: i64,
    print_dependencies: i64,
    spare_dynamic_tags: i64,
    thread_count: i64,
    unique: Option<Glob>,
    physical_image_base: Option<u64>,
    shuffle_sections_seed: Option<u64>,
    pub Map: String,
    chroot: String,
    dependency_file: String,
    pub directory: String,
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
    pub retain_symbols_file: Box<HashSet<&str>>, 
    section_align: HashMap<&str, u64>,
    section_start: HashMap<&str, u64>, 
    ignore_ir_file: HashSet<&str>, 
    pub wrap: HashSet<&str>, 
    section_order: Vec<SectionOrder>,
    defsyms: Vec<(&Symbol, Def)>, 
    pub library_paths: Vec<Path>, 
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

struct VersionPattern {
    pattern: &str,
    ver_idx: u16,
    is_cpp: bool,
}

/// Context represents a context object for each invocation of the linker.
/// It contains command line flags, pointers to singleton objects
/// (such as linker-synthesized output sections), unique_ptrs for
/// resource management, and other miscellaneous objects.
pub struct Context<const MT: MachineType> {
    pub args: Cli,
    version_patterns: Vec<VersionPattern>,
    default_version: u16,
    default_version_from_version_script: bool,
    page_size: i64,

    // Reader context
    as_needed: bool,
    whole_archive: bool,
    pub is_static: bool,
    in_lib: bool,
    file_priority: i64,
    pub visited: HashSet<&str>, 
    tg: tbb::task_group,

    has_error: bool,
    has_lto_object: bool,

    // // Symbol table
    // tbb::concurrent_hash_map<std::string_view, Symbol<E>, HashCmp> symbol_map;
    // TODO: tbb::concurrent_hash_map<std::string_view, ComdatGroup, HashCmp> comdat_groups;
    pub comdat_groups: HashMap<&str, ComdatGroup>,
    // TODO: tbb::concurrent_vector<std::unique_ptr<MergedSection<E>>> merged_sections;
    pub merged_sections: Vec<MergedSection>,
    
    // tbb::concurrent_vector<std::unique_ptr<Chunk<E>>> output_chunks;
    // std::vector<std::unique_ptr<OutputSection<E>>> output_sections;
    // obj_cache: FileCache<E, ObjectFile<E>>,
    // dso_cache: FileCache<E, SharedFile<E>>,

    // tbb::concurrent_vector<std::unique_ptr<TimerRecord>> timer_records;
    // TODO: tbb::concurrent_vector<std::function<void()>> on_exit;
    pub on_exit: Vec<FnMut>,

    // tbb::concurrent_vector<std::unique_ptr<ObjectFile<E>>> obj_pool;
    // tbb::concurrent_vector<std::unique_ptr<SharedFile<E>>> dso_pool;
    // tbb::concurrent_vector<std::unique_ptr<u8[]>> string_pool;
    // tbb::concurrent_vector<std::unique_ptr<MappedFile<Context<E>>>> mf_pool;
    // tbb::concurrent_vector<std::vector<ElfRel<E>>> rel_pool;

    // // Symbol auxiliary data
    // symbol_aux: Vec<SymbolAux>,

    // // Fully-expanded command line args
    // cmdline_args: Vec<&str>,

    // // Input files
    pub objs: Vec<&ObjectFile<E>>,
    pub dsos: Vec<SharedFile<E>>,
    // std::vector<SharedFile<E> *> dsos;
    // ObjectFile<E> *internal_obj = nullptr;

    // // Output buffer
    // std::unique_ptr<OutputFile<Context<E>>> output_file;
    // buf: *const u8,
    // overwrite_output_file: bool,
    
    // chunks: Vec<*const Chunk<E>>,
    // needs_tlsld: AtomicBool,
    // has_gottp_rel: AtomicBool,
    // has_textrel: AtomicBool,

    // // For --warn-once
    // tbb::concurrent_hash_map<void *, int> warned;

    // // Output chunks
    // ehdr: *const OutputEhdr<E>,
    // shdr: *const OutputShdr<E>,
    // phdr: *const OutputPhdr<E>,
    // interp: *const InterpSection<E>,
    // got: *const GotSection<E>,
    // gotplt: *const GotPltSection<E>,
    // relplt: *const RelPltSection<E>,
    // reldyn: *const RelDynSection<E>,
    // relrdyn: *const RelrDynSection<E>,
    // dynamic: *const DynamicSection<E>,
    // strtab: *const StrtabSection<E>,
    // dynstr: *const DynstrSection<E>,
    // hash: *const HashSection<E>,
    // gnu_hash: *const GnuHashSection<E>,
    // shstrtab: *const ShstrtabSection<E>,
    // plt: *const PltSection<E>,
    // pltgot: *const PltGotSection<E>,
    // symtab: *const SymtabSection<E>,
    // dynsym: *const DynsymSection<E>,
    // eh_frame: *const EhFrameSection<E>,
    // eh_frame_hdr: *const EhFrameHdrSection<E>,
    // copyrel: *const CopyrelSection<E>,
    // copyrel_relro: *const CopyrelSection<E>,
    // versym: *const VersymSection<E>,
    // verneed: *const VerneedSection<E>,
    // verdef: *const VerdefSection<E>,
    // buildid: *const BuildIdSection<E>,
    // note_package: *const NotePackageSection<E>,
    // note_property: *const NotePropertySection<E>,
    // gdb_index: *const GdbIndexSection,
    // thumb_to_arm: *const ThumbToArmSection,
    // tls_trampoline: *const TlsTrampolineSection,

    // // For --gdb-index
    // debug_info: *const Chunk<E>,
    // debug_abbrev: *const Chunk<E>,
    // debug_ranges: *const Chunk<E>,
    // debug_addr: *const Chunk<E>,
    // debug_rnglists: *const Chunk<E>,

    // // For --relocatable
    // r_chunks: Vec<RChunk<E> *>;
    // r_ehdr: *const ROutputEhdr<E>,
    // r_shdr: *const ROutputShdr<E>,
    // r_shstrtab: *const RStrtabSection<E>,
    // r_strtab: *const RStrtabSection<E>,
    // r_symtab: *const RSymtabSection<E>,

    // tls_begin: u64,
    // tls_end: u64,
    // relax_tlsdesc: bool,

    // // Linker-synthesized symbols
    // _DYNAMIC: *const Symbol<E>,
    // _GLOBAL_OFFSET_TABLE_: *const Symbol<E>,
    // _TLS_MODULE_BASE_: *const Symbol<E>,
    // __GNU_EH_FRAME_HDR: *const Symbol<E>,
    // __bss_start: *const Symbol<E>, 
    // __ehdr_start: *const Symbol<E>,
    // __executable_start: *const Symbol<E>, 
    // __exidx_end: *const Symbol<E>,
    // __exidx_start: *const Symbol<E>,
    // __fini_array_end: *const Symbol<E>,
    // __fini_array_start: *const Symbol<E>,
    // __global_pointer: *const Symbol<E>,
    // __init_array_end: *const Symbol<E>,
    // __init_array_start: *const Symbol<E>,
    // __preinit_array_end: *const Symbol<E>,
    // __preinit_array_start: *const Symbol<E>,
    // __rel_iplt_end: *const Symbol<E>,
    // __rel_iplt_start: *const Symbol<E>,
    // _edata: *const Symbol<E>,
    // _end: *const Symbol<E>,
    // _etext: *const Symbol<E>,
    // edata: *const Symbol<E>, 
    // end: *const Symbol<E>, 
    // etext: *const Symbol<E>, 
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

impl<const MT: MachineType> Context<MT> {
    pub fn new() -> Self {

    }

    pub fn checkpoint() {
        todo!();
    }

    fn open_library(&self) {

    }

    fn find_library(&self) {

    }

    fn read_file() {

    }
}

fn is_c_identifier(trgt: &str) -> bool {
    if trgt.is_empty() {
        return false;
    }

    

    true
}

fn relax_tlsgd(ctx: &Context<>, sym: &Symbol) -> bool {
    ctx.args.relax && !ctx.args.shared && !sym.is_imported
}

fn relax_tlsld(ctx: &Context<>) -> bool {
    ctx.args.relax && !ctx.args.shared
}

fn relax_tlsdesc(ctx: &Context<>, sym: &Symbol) -> bool {
    // TLSDESC relocs must be always relaxed for statically-linked
    // executables even if -no-relax is given. It is because a
    // statically-linked executable doesn't contain a tranpoline
    // function needed for TLSDESC.
    if ctx.args.is_static {
        return true;
    }

    ctx.args.relax && !ctx.args.shared && !sym.is_imported
}