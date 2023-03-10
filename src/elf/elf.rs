pub enum MachineType {
    NONE, 
    X86_64, 
    I386, 
    ARM64, 
    ARM32, 
    RV64LE, 
    RV64BE, 
    RV32LE, 
    RV32BE,
    PPC64V1, 
    PPC64V2, 
    S390X, 
    SPARC64, 
    M68K,
}

pub const EM_NONE: u32 = 0;
pub const EM_386: u32 = 3;
pub const EM_68K: u32 = 4;
pub const EM_PPC64: u32 = 21;
pub const EM_S390X: u32 = 22;
pub const EM_ARM: u32 = 40;
pub const EM_SPARC64: u32 = 43;
pub const EM_X86_64: u32 = 62;
pub const EM_AARCH64: u32 = 183;
pub const EM_RISCV: u32 = 243;