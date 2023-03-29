// output_tmpfile;
// opt_demangle;

pub static mold_version: &'static str;
pub static mold_product_name: &'static str;
pub static mold_version_string: String;
pub static mold_git_hash: String;

//
// Memory-mapped file
//

// MappedFile represents an mmap'ed input file.
// mold uses mmap-IO only.
pub struct MappedFile {
    name: String,
//     u8 *data = nullptr;
//     i64 size = 0;
//     i64 mtime = 0;
//     bool given_fullpath = true;
//     MappedFile *parent = nullptr;
//     MappedFile *thin_parent = nullptr;
//     int fd = -1;
//   #ifdef _WIN32
//     HANDLE file_handle = INVALID_HANDLE_VALUE;
//   #endif
}

impl MappedFile {
    pub fn open() -> Self {

    }
}