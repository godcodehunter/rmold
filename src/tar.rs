use crate::mold::align_to;
use std::{
    fs::File,
    io::{Seek, Write}, path::Path,
};

/// A tar file consists of one or more Ustar header followed by data.
/// Each Ustar header represents a single file in an archive.
///
/// tar is an old file format, and its `name` field is only 100 bytes long.
/// If `name` is longer than 100 bytes, we can emit a PAX header before a
/// Ustar header to store a long filename.
///
/// For simplicity, we always emit a PAX header even for a short filename.
#[repr(C)]
struct UstarHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    checksum: [u8; 8],
    typeflag: [u8; 1],
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    devmajor: [u8; 8],
    devminor: [u8; 8],
    prefix: [u8; 155],
    pad: [u8; 12],
}

/// The `Default` trait is implemented manually because the `Default` macro in Rust
/// only supports arrays types with a length up to 32 characters.
/// When the const-generic implementation is added (https://github.com/rust-lang/rust/issues/61415),
/// the ad-hoc implementation can be refactored.
impl Default for UstarHeader {
    fn default() -> Self {
        UstarHeader {
            name: [0; 100],
            mode: [0; 8],
            uid: [0; 8],
            gid: [0; 8],
            size: [0; 12],
            mtime: [0; 12],
            checksum: [0; 8],
            typeflag: [0; 1],
            linkname: [0; 100],
            magic: [0; 6],
            version: [0; 2],
            uname: [0; 32],
            gname: [0; 32],
            devmajor: [0; 8],
            devminor: [0; 8],
            prefix: [0; 155],
            pad: [0; 12],
        }
    }
}

impl UstarHeader {
    // Represent whole struct as byte slice 
    fn as_slice(&self) -> &[u8] {
        let size = std::mem::size_of::<Self>();
        let pointer = self as *const Self;
        let bytes = unsafe { std::slice::from_raw_parts(pointer as *const u8, size) };
        bytes
    }

    // Set `magic`, `version` and `checksum`
    fn finalize(&mut self) {
        self.checksum.fill(b' ');
        self.magic.copy_from_slice(b"ustar");
        self.version.copy_from_slice(b"00");

        let bytes = self.as_slice();
        let sum = bytes.iter().fold(0 as i64, |acc, x| acc + (*x as i64));

        write!(&mut self.checksum[..], "{:06o}", sum).unwrap();
    }
}

fn encode_path(basedir: Path, path: Path) -> String {
    path = path_clean(basedir + "/" + path);

    // Construct a string which contains something like
    // "16 path=foo/bar\n" where 16 is the size of the string
    // including the size string itself.
    let len = " path=\n".len() + path.len();
    let mut total = len.to_string().len() + len;
    total = total.to_string().len() + len;
    total.to_string() + " path=" + &path + "\n"
}

// TarFile is a class to create a tar file.
//
// If you pass `--repro` to mold, mold collects all input files and
// put them into `<output-file-path>.repro.tar`, so that it is easy to
// run the same command with the same command line arguments.
struct TarWriter {
    out: File,
    basedir: Path,
}

impl TarWriter {
    const BLOCK_SIZE: usize = 512;

    pub fn open(output_path: Path, basedir: Path) -> Result<Self, std::io::Error> {
        let out = File::create(output_path)?;
        Ok(Self { out, basedir })
    }   

    pub fn append(&mut self, path: Path, data: &[u8]) -> Result<(), std::io::Error> {
        // Write PAX header
        let mut pax = UstarHeader::default();
        let attr = encode_path(self.basedir, path);
        write!(&mut pax.size[..], "{:011o}", attr.len()).unwrap();
        pax.typeflag[0] = b'x';
        pax.finalize();
        self.out.write(pax.as_slice())?;

        // Write pathname
        self.out.write(attr.as_bytes())?;
        let offset = align_to(self.out.stream_position()?, Self::BLOCK_SIZE);
        self.out.seek(std::io::SeekFrom::Start(offset))?;

        // Write Ustar header
        let mut ustar = UstarHeader::default();
        ustar.mode.copy_from_slice("0000664");
        write!(&mut ustar.size[..], "{:011o}", data.len()).unwrap();
        ustar.finalize();
        self.out.write(ustar.as_slice())?;

        // Write file contents
        self.out.write(data)?;
        let offset = align_to(self.out.stream_position()?, Self::BLOCK_SIZE);
        self.out.seek(std::io::SeekFrom::Start(offset))?;

        // A tar file must ends with two empty blocks, so write such
        // terminator and seek back.
        let terminator = [0u8; Self::BLOCK_SIZE * 2];
        self.out.write(&terminator)?;
        self.out.seek(std::io::SeekFrom::End(-Self::BLOCK_SIZE * 2))?;

        debug_assert!(self.out.stream_position() % Self::BLOCK_SIZE == 0);

        Ok(())
    }
}
