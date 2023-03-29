mod elf;
mod mold;
mod mapfile;

use crate::mold;
use crate::filetype;
use crate::elf;

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

fn new_lto_obj() {

}

fn new_shared_file() {

}

fn read_file(&ctx: Context<E>, mf: *const MappedFile<Context<E>>) {
    if (ctx.visited.contains(mf->name))
        return;

    
}

fn deduce_machine_type() {

}

fn open_library() {

}

fn find_library() {

}

fn read_input_files() {

}

fn show_stats() {

}

fn redo_main() {

}

use clap::{Parser, Subcommand};
use std::{process::Command, path::{PathBuf, Path}};

#[derive(Parser)]
struct Cli {
   #[command(subcommand)]
   run: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 
    Run { prog: PathBuf, args: Vec<PathBuf>},
}

fn get_self_path() -> PathBuf {
    std::env::current_exe().unwrap().file_name().unwrap()
}

fn get_dso_path(prog: PathBuf) -> PathBuf {
    let paths = [
        prog.parent().unwrap().join(Path::new("mold-wrapper.so")),
        Path::new(env!("MOLD_LIBDIR")).join(Path::new("/mold/mold-wrapper.so")),
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
        Commands::Run { prog, args} => { 
            if cfg!(not(target_family = "unix")) {
                panic!("subcommand run is supported only on Unix family os system");
            }
            
            let self_path = get_self_path();
            let dso_path = get_dso_path(&self_path);

            let mut real_prog = prog;
            let args = std::env::args().skip(3);
            
            let file_name = prog.file_name().unwrap().to_str();
            if matches!(file_name, Some("ld" | "ld.lld" | "ld.gold")) {
                real_prog = &self_path;
            }

            Command::new(real_prog)
                .env("LD_PRELOAD", self_path)
                .env("MOLD_PATH", dso_path)
                .args(args)
                .spawn()
                .expect("TODO TODO TODO");
        }
    }

    // If no -m option is given, deduce it from input files.
    if ctx.args.emulation == MachineType::NONE {
        ctx.args.emulation = deduce_machine_type()
    }
}