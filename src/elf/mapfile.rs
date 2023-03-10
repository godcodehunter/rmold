use rayon::{prelude::{IntoParallelRefMutIterator, ParallelIterator, IntoParallelRefIterator}, collections::hash_map};

use crate::InputSection;

use super::mold::{Context, Symbol, ChunkKind};
use std::{fs::File, io::{self, Write}};
use std::collections::HashMap;

// TODO: tbb::concurrent_hash_map<InputSection<E> *, std::vector<Symbol<E> *>>;
type Map<E> = HashMap<&InputSection<E>, Vec<&Symbol<E>>>;

fn open_output_file<E>(ctx: &Context<E>) -> File {
    let msg = format!("cannot open {}", ctx.args.Map);
    File::create(ctx.args.Map)
    // TODO: Fatal(ctx) << "cannot open " << ctx.arg.Map << ": " << errno_string();
        .expect(msg.as_str())
}

fn get_map<E>(ctx: &Context<E>) -> Map<E> {
    let map = Map::<E>::new();

    // TODO: tbb::parallel_for_each
    ctx.objs.par_iter().for_each(|file| {
        for sym in file.parent.symbols {
            if sym.file != file || sym.get_type() == STT_SECTION {
                continue;
            }

            if let Some(isec) = sym.get_input_section() {
                assert!(file == isec.file);
                map[isec].push_back(sym);
            }
        }
    });

    if map.len() <= 1 {
        return map;
    } 

    // TODO: tbb::parallel_for_each
    for (_, v) in &mut map {
        v.sort()
    }

    map
}

fn print_map<E>(ctx: &Context<E>) {
    let mut target: &dyn Write = &io::stdout();

    if !ctx.args.Map.is_empty() {
        target = &open_output_file(ctx);
    }

    let map = get_map(ctx);

    writeln!(target, "               VMA       Size Align Out     In      Symbol");

    for osec in ctx.chunks {
        writeln!(
            target, 
            "{:>18x}{:>11}{:>6} {}", 
            osec.shdr.sh_addr, 
            osec.shdr.sh_size, 
            osec.shdr.sh_addralign,
            osec.name
        );
        
        if osec.kind() != ChunkKind::OUTPUT_SECTION {
            continue;
        }

        let members = (osec as &OutputSection<E>).members;
        let mut buff = Vec::<String>::with_capacity(members.len());

        // TODO: tbb::parallel_for
        for i in 0..=members.len() {
            let member = members[i];
            let mut s_tmp = String::new();
            let addr = osec.shdr.sh_addr + member.offset;

            writeln!(
                s_tmp,
                "{:>18x}{:>11}{:>6}         {}",
                addr,
                member.sh_size,
                member.p2align,
                member
            );
            
            // TODO: concurrent map 
            if Some(symbols) = map.get(member) {
                for sym in symbols {
                    writeln!(
                        s_tmp,
                        "{:>18x}{:>11}{:>6}                 {}", 
                        sym.get_addr(ctx),
                        0,
                        0,
                        sym
                    );
                }
            }

            buff[i] = s_tmp;
        }

        for item in buff {
            target.write(item.as_bytes());
        }
    }
}