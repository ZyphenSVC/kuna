//! (kuna) `envpelide` — leave an unread `envp` out of `main`'s printed
//! declaration (P9 emit).
//!
//! The C runtime calls `main(argc, argv, envp)`, and `elfmain` declares exactly
//! that, LOCKED, because declaring two parameters would delete a live third one
//! from a `main` that forwards it (see `kuna_elfmain`'s header in
//! `kuna-analysis`). Most programs never read `envp`, though, and the source they
//! were compiled from says `int main(int argc, char **argv)`. Analysis keeps the
//! three-parameter lock; only the printed declaration drops the trailing `envp`
//! when the decompiled body has no reader of its incoming value.
//!
//! The parameter list is left alone everywhere else: a call to `main` still
//! passes three arguments (the callee prototype a caller copies is the parked
//! one), and the body's own names and types do not depend on the choice. The
//! `decompile-all --json` variable list follows the printed declaration, so a
//! hidden `envp` is not reported as a parameter either.
//!
//! The declaration is recognised by what it says, not by where it came from:
//! a function named `main` whose locked, non-variadic prototype has exactly three
//! inputs, the third named `envp` and typed as a pointer to a pointer to a byte.
//! That is `elfmain`'s declaration on a stripped and an unstripped image alike,
//! so both builds of one program print the same signature; a debug-info
//! declaration spelled identically is indistinguishable from it and is treated
//! the same. A host-owned prototype (Ghidra mode) is never touched.

use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use crate::architecture::Architecture;
use crate::context::VarnodeId;
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;
use crate::varnode::varnode_flags;

/// How many trailing declared parameters the printed declaration of `fd`
/// leaves out: 1 for an unread `envp` of `main`, else 0.
pub fn hidden_params(arch: &Architecture, fd: &Funcdata) -> int4 {
    if !arch.envpelide || arch.remote_scope.is_some() || fd.get_display_name() != "main" {
        return 0;
    }
    let proto = fd.get_func_proto();
    if !proto.has_store() || !proto.is_input_locked() || proto.is_dotdotdot() || proto.num_params() != 3 {
        return 0;
    }
    let Some(envp) = proto.get_param(2) else { return 0 };
    if envp.get_name() != "envp" || !envp.get_type().is_some_and(|t| pointer_to_byte_pointer(&t)) {
        return 0;
    }
    let (addr, size) = (envp.get_address(), envp.get_size());
    let inputs: Vec<VarnodeId> = fd
        .vbank()
        .iter_def_flag(varnode_flags::input)
        .filter(|&id| fd.vbank().get(id).is_some_and(|vn| vn.intersects_range(&addr, size)))
        .collect();
    if reaches_a_reader(fd, inputs) {
        0
    } else {
        1
    }
}

/// How many values [`reaches_a_reader`] follows before it answers yes.
const MAX_VALUES: usize = 64;

/// Does any of `start` reach an op that reads it, through the copies a call's
/// possible side effects (`INDIRECT`) and a control-flow join (`MULTIEQUAL`)
/// make of it? A stack-passed `envp` whose frame address the body takes (gcc's
/// i386 `main` realigns the stack through `lea 0x4(%esp),%ecx`) is carried past
/// every call that way and read by none of them.
fn reaches_a_reader(fd: &Funcdata, start: Vec<VarnodeId>) -> bool {
    let mut seen: Vec<VarnodeId> = Vec::new();
    let mut work = start;
    while let Some(vn) = work.pop() {
        if seen.contains(&vn) {
            continue;
        }
        if seen.len() >= MAX_VALUES {
            return true;
        }
        seen.push(vn);
        for op in fd.descend_snapshot(vn) {
            let Some(o) = fd.obank().get(op) else { return true };
            match o.code() {
                OpCode::CPUI_INDIRECT | OpCode::CPUI_MULTIEQUAL => {
                    if let Some(out) = o.get_out() {
                        work.push(out);
                    }
                }
                _ => return true,
            }
        }
    }
    false
}

/// `char **` and its signed/unsigned/undefined-byte spellings.
fn pointer_to_byte_pointer(ty: &Datatype) -> bool {
    let byte = |t: &Datatype| {
        t.get_size() == 1
            && matches!(
                t.get_metatype(),
                type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN
            )
    };
    ty.get_metatype() == type_metatype::TYPE_PTR
        && ty.get_ptr_to().is_some_and(|p| {
            p.get_metatype() == type_metatype::TYPE_PTR && p.get_ptr_to().is_some_and(|c| byte(&c))
        })
}
