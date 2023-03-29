mod elf;
mod mold;
mod mapfile;

use crate::mold;
use crate::filetype;
use crate::elf;
use crate::mold::MappedFile;
use crate::perf::Counter;

use self::elf::MachineType;
use self::mold::Context;

// Read the beginning of a given file and returns its machine type
// (e.g. EM_X86_64 or EM_386).
fn get_machine_type(mf: &mold::MappedFile) -> elf::MachineType {
    fn get_elf_type() {
        let is_le = ;
        let is_64;
        let e_machine;

        if is_le {

        } else {
            
        }

        return match e_machine {
            elf::EM_386 => elf::MachineType::I386,
            elf::EM_X86_64 => elf::MachineType::X86_64,
            elf::EM_ARM => elf::MachineType::ARM32,
            elf::EM_AARCH64 => elf::MachineType::ARM64,
            elf::EM_RISCV => {
                if is_le {
                    return if is_64 {
                        elf::MachineType::RV64LE
                    } else {
                        elf::MachineType::RV32LE
                    };
                }
                
                return if is_64 {
                    elf::MachineType::RV64BE
                } else {
                    elf::MachineType::RV32BE
                };
            },
            elf::EM_PPC64 => if is_le { elf::MachineType::PPC64V2 } else { elf::MachineType::PPC64V1 },
            elf::EM_S390X => elf::EM_S390X,
            elf::EM_SPARC64 => elf::MachineType::SPARC64,
            elf::EM_68K => elf::MachineType::M68K,
            _ => elf::MachineType::NONE,
        };
    }

    match filetype::get_file_type(mf) {
        filetype::FileType::UNKNOWN => todo!(),
        filetype::FileType::EMPTY => todo!(),
        filetype::FileType::ELF_OBJ => todo!(),
        filetype::FileType::ELF_DSO => todo!(),
        filetype::FileType::MACH_OBJ => todo!(),
        filetype::FileType::MACH_DYLIB => todo!(),
        filetype::FileType::MACH_UNIVERSAL => todo!(),
        filetype::FileType::AR => todo!(),
        filetype::FileType::THIN_AR => todo!(),
        filetype::FileType::TAPI => todo!(),
        filetype::FileType::TEXT => todo!(),
        filetype::FileType::GCC_LTO_OBJ => todo!(),
        filetype::FileType::LLVM_BITCODE => todo!(),
    }
}

fn check_file_compatibility(ctx: &Context, mf: &mold::MappedFile) {
    let mt = get_machine_type(mf);
    if mt != ctx.arg.emulation {
        todo!()
    }
}

fn new_object_file(ctx: &Context<E>, mf: *const MappedFile<Context<E>>, archive_name: String) {

}

fn new_lto_obj<const MT: MachineType>(ctx: &Context<MT>) -> Option<> {
    if ctx.args.ignore_ir_file {

    }

    let mut file = read_lto_object(ctx, mf);
    file.priority = ctx.file_priority
    file.archive_name = archive_name;
    file.is_in_lib = ;
    file.is_alive = ;
}

fn new_shared_file() {

}

fn read_file(ctx: &Context<E>, mf: *const MappedFile<Context<E>>) {
    if (ctx.visited.contains(mf->name))
        return;

    
}

fn deduce_machine_type() {

}

fn open_library<const MT: MachineType>(ctx: &Context<MT>, path: Path) -> Option<> {
    if let Some(mf) = MappedFile::open(ctx, path) {
        return mf;
    }

    let ty = get_machine_type(ctx, mf);
    if ty == MachineType::NONE || ty == MT {
        return mf;
    }
    println!("WARN: {}: skipping incompatible file {}", path, ty);

    None
}

fn find_library<const MT: MachineType>(ctx: &Context<MT>, name: Path) {
    if name.starts_with(':') {
        for dir in ctx.args.library_paths {
            name = name.strip_prefix(":").unwrap();
            let path = dir.join(name);
            if Some(mf) = open_library(ctx, path) {
                return mf;
            }
        }
        panic!("library not found: {}", name.as_ref());
    }

    for dir in ctx.args.library_paths {
        let mut stem = dir.join("lib").join(name);
        if !ctx.is_static {
            stem.set_extension(".so");
            if Some(mf) = open_library(ctx, path) {
                return mf;
            }
        }
        stem.set_extension(".a");
        if Some(mf) = open_library(ctx, path) {
            return mf;
        }
    }

    panic!("library not found: {}", name.as_ref());
}

fn read_input_files<const MT: MachineType>(ctx: &Context<MT>)  {
    
}

fn show_stats<const MT: MachineType>(ctx: &Context<MT>) {
    for obj in ctx.objs {
        let defined_syms = Counter::builder().name("defined_syms").build();
        defined_syms.add(obj.parent.first_global - 1);
        
        let undefinde_syms = Counter::builder().name("undefined_syms").build();
        undefinde_syms.add(obj.parent.symbols.len() - obj.parent.first_global);

        let alloc = Counter::builder().name("reloc_alloc").build();
        let nonalloc = Counter::builder().name("reloc_alloc").build();
        
        obj.sections.iter()
            .filter(|sec| sec.is_alive.load())
            .for_each(|sec| {
                let len = sec.get_rels().len();
                if sec.shdr().sh_flags & SHF_ALLOC {
                    alloc.add(len);
                } else {
                    nonalloc.add(len);
                }
            });

        let comdats = Counter::builder().name("comdats").build();
        comdats.add(obj.comdat_groups.len());

        let removed_comdats = Counter::builder().name("removed_comdat_mem").build();
        for (group, span) in obj.comdat_groups {
            if group.owner != obj.priority {
                removed_comdats.add(span.len());
            }
        }

        let num_cies = Counter::builder().name("num_cies").build();
        num_cies.add(obj.cies.len());

        let num_unique_cies = Counter::builder().name("num_unique_cies").build();
        for cie in obj.cies {
            if cie.is_leader {
                num_unique_cies.inc();
            }
        }

        let num_fdes =  Counter::builder().name("num_fdes").build();
        num_fdes.add(obj.fdes.len());
    }

    let num_bytes = Counter::builder().name("num_fdes").build();
    for mf in ctx.mf_pool {
        num_bytes.add(mf.len());
    }
    let num_input_sections = Counter::builder().name("input_sections").build();
    for file in ctx.objs {
        num_input_sections.add(file.sections.len());
    }

    let num_output_chunks = Counter::builder().name("output_chunks").build();
    let num_objs = Counter::builder().name("num_objs").build();
    let num_dsos = Counter::builder().name("num_dsos").build();

    num_output_chunks.add(ctx.chunks.len());
    num_objs.add(ctx.objs.len());
    num_dsos.add(ctx.dsos.len());

    if MT.is_need_thunk() {
        let thunk_bytes = Counter::builder().name("thunk_bytes").build();
        for osec in ctx.output_sections {
            for thunk in osec.thunk {
                thunk_bytes.add(thunk.len()); 
            }
        }
    }

    crate::perf::Stats::print();

    for sec in ctx.merged_sections {
        sec.print_stats()
    }
}

fn redo_main() {

}

use clap::{Parser, Subcommand};
use std::process::exit;
use std::{process::Command, path::{PathBuf, Path}};

#[derive(Parser)]
struct Cli {
   #[command(subcommand)]
   run: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run { target: PathBuf, args: Vec<PathBuf>},
}

/// Finds the first existing path to `mold-wrapper.so` file in the 
/// following directories: 
/// 
/// * `{PROG_DIR}/mold-wrapper.so` - same directory as the executable is
/// * `${MOLD_LIBDIR}/mold/mold-wrapper.so` - which is /usr/local/lib/mold by default
/// * `{ALL_P_D}../lib/mold/mold-wrapper.so` - 
/// 
/// panics if it doesn't.
fn get_dso_path(prog: PathBuf) -> PathBuf {
    let paths = [
        prog.parent().unwrap().join(Path::new("mold-wrapper.so")),
        Path::new(env!("MOLD_LIBDIR")).join(Path::new("mold/mold-wrapper.so")),
        prog.parent().unwrap().join(Path::new("../lib/mold/mold-wrapper.so")),
    ];
    
    for path in paths {
        if path.is_file() {
            return path;
        }
    }
    
    panic!("mold-wrapper.so is missing");
}

pub fn main<const MT: MachineType>() {
    let ctx = Context::<MT>::new();
    let cli = Cli::parse();
    
    match &cli.run {
        Commands::Run { target, args} => { 
            if cfg!(not(target_family = "unix")) {
                panic!("subcommand run is supported only on Unix family os system");
            }
            
            let self_path = std::env::current_exe().unwrap().file_name().unwrap();
            let dso_path = get_dso_path(&self_path);

            let mut real_prog = target;
            let args = std::env::args().skip(3);
            
            let file_name = target.file_name().unwrap().to_str();
            if matches!(file_name, Some("ld" | "ld.lld" | "ld.gold")) {
                real_prog = &self_path;
            }

            Command::new(real_prog)
                .env("LD_PRELOAD", self_path)
                .env("MOLD_PATH", dso_path)
                .args(args)
                .spawn()
                .expect("target launch error");
        }
    }

    todo!();
    // Parse non-positional command line options
    // ctx.cmdline_args = expand_response_files(ctx, argv);
    // std::vector<std::string> file_args = parse_nonpositional_args(ctx);

    // If no -m option is given, deduce it from input files.
    if ctx.args.emulation == MachineType::NONE {
        ctx.args.emulation = deduce_machine_type()
    }

    todo!();
    // // Redo if -m is not x86-64.
    //   if constexpr (std::is_same_v<E, X86_64>)
    //   if (ctx.arg.emulation != MachineType::X86_64)
    //     return redo_main<E>(argc, argv, ctx.arg.emulation);

    Timer t_all(ctx, "all");

    if !ctx.args.directory.is_empty() {
        
    }

    if ctx.arg.relocatable {
        combine_objects(ctx, file_args);
        return;
    }

    for name in ctx.args.wrap {
        get_symbol(ctx, name).wrap = true;
    }

    for name in ctx.arg.retain_symbols_file {
        get_symbol(ctx, name).write_to_symtab = true;
    }

    // Close the output file. This is the end of the linker's main job.
    ctx.output_file->close(ctx);

    if !ctx.args.dependency_file.is_empty() {
        write_dependency_file(ctx);
    }

    if ctx.has_lto_object {
        lto_cleanup(ctx);
    }

    t_total.stop();
    t_all.stop();

    if ctx.args.print_map {
        mapfile::print_map(ctx);
    }

    if ctx.args.stats {
        show_stats(ctx)
    }

    if ctx.args.perf {
        print_timer_records(ctx.timer_records)
    }

    if on_complete {
        on_complete = fork_child();
    }

    if ctx.args.quick_exit {
        todo!();   
    }
    
    ctx.on_exit.for_each(|f| f());
    ctx.checkpoint();
}