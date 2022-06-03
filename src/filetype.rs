enum FileType {
    UNKNOWN,
    EMPTY,
    ELF_OBJ,
    ELF_DSO,
    MACH_OBJ,
    MACH_DYLIB,
    MACH_UNIVERSAL,
    AR,
    THIN_AR,
    TAPI,
    TEXT,
    GCC_LTO_OBJ,
    LLVM_BITCODE,
}

fn is_text_file(mf: *const MappedFile<C>) -> bool {

}

fn is_gcc_lto_obj(mf: *const MappedFile<C>) {

}

fn get_file_type(mf: *const MappedFile<C>) -> FileType {
    let data = mf.get_contents();

    if data.empty() {
        return FileType::EMPTY;
    }

    if data.start_with("\177ELF") {
        data.data() + 12;
        
        case 1:
        elf::Elf32Ehdr &ehdr = *(elf::Elf32Ehdr *)data.data();
        
        if (ehdr.e_ident[elf::EI_CLASS] == elf::ELFCLASS32) {
            if is_gcc_lto_obj<elf::I386>(mf) {
                return FileType::GCC_LTO_OBJ;
            }
        } else {
            if is_gcc_lto_obj<elf::X86_64>(mf) {
                return FileType::GCC_LTO_OBJ;
            }
        }

        return FileType::ELF_OBJ;
        
        case 3:
        return FileType::ELF_DSO;

        return FileType::UNKNOWN;
    }

    if data.starts_with("\xcf\xfa\xed\xfe") {
        data.data() + 12;
        case 1:
        return FileType::MACH_OBJ;
        case 6:
        return FileType::MACH_DYLIB;

        return FileType::UNKNOWN;
    }

    if data.start_with("!<arch>\n") {
        return FileType::AR;
    }
    if data.start_with("!<thin>\n") {
        return FileType::THIN_AR;
    }
    if data.start_with("--- !tapi-tbd") {
        return FileType::TAPI;
    }
    if data.start_with("\xca\xfe\xba\xbe") {
        return FileType::MACH_UNIVERSAL;
    }
    if is_text_file(mf) {
        return FileType::TEXT;
    }
    if data.starts_with("\xde\xc0\x17\x0b") {
        return FileType::LLVM_BITCODE;
    }
    if data.starts_with("BC\xc0\xde") {
        return FileType::LLVM_BITCODE;
    }
    return FileType::UNKNOWN;
}