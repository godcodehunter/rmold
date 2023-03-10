mod elf;
mod mold;
mod mapfile;

use crate::mold;
use crate::filetype;
use crate::elf;

use self::elf::MachineType;

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

fn elf_main() {
 
}