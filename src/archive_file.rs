// This file contains functions to read an archive file (.a file).
// An archive file is just a bundle of object files. It's similar to
// tar or zip, but the contents are not compressed.
//
// An archive file is either "regular" or "thin". A regular archive
// contains object files directly, while a thin archive contains only
// pathnames. In the latter case, actual file contents have to be read
// from given pathnames. A regular archive is sometimes called "fat"
// archive as opposed to "thin".
//
// If an archive file is given to the linker, the linker pulls out
// object files that are needed to resolve undefined symbols. So,
// bunding object files as an archive and giving that archive to the
// linker has a different meaning than directly giving the same set of
// object files to the linker. The former links only needed object
// files, while the latter links all the given object files.
//
// Therefore, if you link libc.a for example, not all the libc
// functions are linked to your binary. Instead, only object files
// that provides functions and variables used in your program get
// linked. To make this efficient, static library functions are
// usually separated to each object file in an archive file. You can
// see the contents of libc.a by runnning `ar t
// /usr/lib/x86_64-linux-gnu/libc.a`.
use std::{str, slice::from_raw_parts};

use crate::{Context, mold::MappedFile, filetype::{FileType, get_file_type}};

struct ArHdr {
    ar_name: [char; 16],
    ar_date: [char; 12],
    ar_uid: [char; 6],
    ar_gid: [char; 6],
    ar_mode: [char; 8],
    ar_size: [char; 10],
    ar_fmag: [char; 2],
}

impl ArHdr {
    fn starts_with(&self, s: &str) -> bool {
        self.ar_name.starts_with(s)
    }

    fn is_strtab(&self) -> bool {
        self.starts_with("// ")
    }

    fn is_symtab(&self) -> bool {
        self.starts_with("/ ") || self.starts_with("/SYM64/ ")
    }

    fn read_name(&self, strtab: &str, ptr: *const u8) -> &[u8] {
        // BSD-style long filename
        if self.starts_with("#1/") {
            let name_len = str::from_utf8(self.ar_name[3..]) //TODO
                .unwrap()
                .parse::<i32>(); //TODO

            unsafe {
                let name = from_raw_parts(ptr, name_len);

                if let Some(pos)  = name.find('\0') {
                    name = &name[..=pos];
                }

                return name;
            }
        }

        // SysV-style long filename
        if self.starts_with("/") {
            let start = str::from_utf8(self.ar_name[1..])
                .unwrap()
                .parse::<i32>() //TODO
                .unwrap();
            let end = strtab[start..].find("/\n");
            return strtab[start..=end];
        }

        // Short fileanme
        if let Some(pos) = str::from_utf8(self.ar_name).unwrap().find('/') { //TODO
            return self.ar_name[..=pos];
        }

        self.ar_name
    }
}

fn read_thin_archive_members<'a, E>(ctx: &Context<E>, mf: &MappedFile) -> Vec<&'a MappedFile> {
    let begin = mf.data;
    let data = begin + 8;
    let buff = Vec::<&MappedFile>::new();
    let strtab: &str;

    while data < begin + mf.len {
        // Each header is aligned to a 2 byte boundary.
        if (begin - data) % 2 {
            data += 1;
        }

        let hdr = data as &ArHdr;
        let body = data + std::mem::size_of::<ArHdr>();
        let size = str::from_utf8(hdr.ar_size)
        .unwrap()
        .parse::<i32>() //TODO
        .unwrap();

        // Read if string table
        if hdr.is_strtab() {
            unsafe {
                strtab = std::slice::from_raw_parts(body, size);
            }
            data = body + size;
            continue;
        }

        // Skip a symbol table.
        if hdr.is_symtab() {
            data = body + size;
            continue;
        }

        if !hdr.starts_with("#1/") && !hdr.starts_with("/") {
            panic!("{}: filename is not stored as a long filename", mf.name);
        }

        let name = hdr.read_name(strtab, body);

        // Skip if symbol table
        if name == "__.SYMDEF" || name == "__.SYMDEF SORTED" {
            continue;
        }

        let path = if name.starts_with('/') {
            name
        } else {
            std::path::Path::new(mf.name)
                .parent()
                .unwrap()
                .join(name);                
        };

        let tmp = ctx.open_file(path);
        tmp.thin_parent = mf;
        buff.push(&tmp);
        data = body;
    }

    buff
}

fn read_fat_archive_members<'a, E>(ctx: &Context<E>, mf: &MappedFile) -> Vec<&'a MappedFile> {
    let begin = mf.data;
    let data = begin + 8;
    let buff = Vec::<&MappedFile>::new();
    let strtab: &str;

  while begin + mf.size - data >= 2 {
    if (begin - data) % 2 {
        data += 1;
    }

    let hdr = data as &ArHdr;
    let body = data + std::mem::size_of::<ArHdr>();
    let size = str::from_utf8(hdr.ar_size)
        .unwrap()
        .parse::<i32>() //TODO
        .unwrap();
    data = body + size;

    // Read if string table
    if hdr.is_strtab() {
        unsafe {
            strtab = std::slice::from_raw_parts(body, size);
        }
        continue;
    }

    // Skip if symbol table
    if hdr.is_symtab() {
        continue;
    }

    // Read the name field
    let name = hdr.read_name(strtab, body);

    // Skip if symbol table
    if name == "__.SYMDEF" || name == "__.SYMDEF SORTED" {
        continue;
    }

    buff.push(ctx.slice(mf, name, body - begin, data - body));
  }

  buff
}

pub fn read_archive_members<'a, E>(ctx: &Context<E>, mf: &MappedFile) -> Vec<&'a MappedFile> {
    match get_file_type(mf) {
        FileType::AR => read_fat_archive_members(ctx, mf),
        FileType::THIN_AR => read_thin_archive_members(ctx, mf),
        _ => unreachable!()
    }
}