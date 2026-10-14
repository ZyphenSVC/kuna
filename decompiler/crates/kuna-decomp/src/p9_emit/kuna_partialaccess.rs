//! (kuna `partialaccess`) Print a partial access of a variable that no member
//! names as a typed pointer access instead of Ghidra's `name._<off>_<size>_`.
//!
//! `PrintC::pushPartialSymbol` (printc.cc:2106-2117) renders the bytes of a
//! variable that no field covers as an artificial member, `v1._4_2_` for the two
//! bytes at offset 4. That is not C: no compiler accepts it and a reader has to
//! know the convention. With the option on, the same access prints as the
//! pointer access it is, the spelling kuna already uses for the same bytes
//! reached through a pointer:
//!
//! * `((T *)&v1)[k]` when the offset is a multiple of the width (`k` = offset /
//!   width), which is IDA's `WORDn`/`BYTEn` reading;
//! * `*(T *)&v1` at offset 0;
//! * `*(T *)((char *)&v1 + off)` for an unaligned offset;
//! * `*(T *)&buf[off]`, and `*(T *)buf` at offset 0, when the bytes are taken
//!   out of a byte array, whose subscripts already count bytes;
//! * the bare `buf` for all of an array wider than any C scalar, the 16 bytes
//!   of a vector or register-pair container;
//! * `((char *)&v1)[off]` where the caller takes the address of a position
//!   inside the variable rather than reading bytes.
//!
//! `T` is the accessed value's own type when it is a scalar of exactly the
//! access width, else the unknown type of that width -- or a float of that width
//! when an unknown-typed access carries a float value (a float operation wrote
//! or reads it, or it copies one), since an integer `T` would make C convert
//! the value where the binary moves its bits. C has no scalar of 3, 5,
//! 6, 7 or more than 8 bytes, so such an access names its bytes as kuna's
//! existing loads of that width do, `*(char (*)[7])((char *)&v + 1)`: explicit
//! about the width, but a value C cannot hold, like the `CONCAT71`/`SUB1612`
//! intrinsics such accesses appear in. The member path in front
//! of the token is kept (`((unsigned int *)&v1.flagfield)[1]`). Every form is an
//! lvalue, so a partial store prints the same way. The offset is the byte offset into the
//! variable's storage, as it is for the token it replaces, so the reading is the
//! target's memory order on every architecture.

use std::rc::Rc;

use kuna_base::types::{int4, int8};

use crate::architecture::Architecture;
use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;

/// Which pointer form an access takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// `((T *)&v)[k]`.
    Index(int8),
    /// `*(T *)&v`.
    Base,
    /// `*(T *)((char *)&v + off)`.
    Bytes(int8),
    /// `*(T *)&v[k]`, in a byte array.
    Element(int8),
    /// `*(T *)v`, the start of a byte array.
    Decay,
    /// `v`: all of an array no C scalar is as wide as.
    Whole,
}

/// The planned rendering of one partial access.
pub struct Piece {
    /// The pointer form.
    pub form: Form,
    /// `T *`.
    pub pointer: Rc<Datatype>,
    /// `char *`, for [`Form::Bytes`].
    pub bytes: Option<Rc<Datatype>>,
}

/// A scalar value type spelled at exactly `size` bytes: the only kind a
/// dereference can assign or compare as a whole (an array or an aggregate of
/// the access width would print `*(char (*)[16])&v = 0`).
fn readable(ct: &Datatype, size: int4) -> bool {
    ct.get_size() == size
        && (matches!(size, 1 | 2 | 4 | 8) || ct.get_metatype() == type_metatype::TYPE_FLOAT)
        && matches!(
            ct.get_metatype(),
            type_metatype::TYPE_INT
                | type_metatype::TYPE_UINT
                | type_metatype::TYPE_BOOL
                | type_metatype::TYPE_FLOAT
                | type_metatype::TYPE_PTR
                | type_metatype::TYPE_UNKNOWN
        )
}

/// Does the access carry a floating-point value its own unknown type does not
/// say: written by a float operation or a copy of a float, or read by a float
/// operation?  An integer `T` would make C convert the value instead of moving
/// its bits.
pub(crate) fn carries_float(fd: &Funcdata, vn: VarnodeId, op: OpId) -> bool {
    use kuna_num::opcodes::OpCode;
    let Some(v) = fd.vbank().get(vn) else { return false };
    let Some(o) = fd.obank().get(op) else { return false };
    if v.get_def() == Some(op) {
        let input_float = o
            .get_in(0)
            .and_then(|i| fd.vbank().get(i))
            .is_some_and(|i| i.get_type().get_metatype() == type_metatype::TYPE_FLOAT);
        return match o.code() {
            OpCode::CPUI_COPY => input_float,
            c => crate::kuna_ptrfromuse::is_float_op(c)
                && !matches!(
                    c,
                    OpCode::CPUI_FLOAT_EQUAL
                        | OpCode::CPUI_FLOAT_NOTEQUAL
                        | OpCode::CPUI_FLOAT_LESS
                        | OpCode::CPUI_FLOAT_LESSEQUAL
                        | OpCode::CPUI_FLOAT_NAN
                        | OpCode::CPUI_FLOAT_TRUNC
                ),
        };
    }
    match o.code() {
        OpCode::CPUI_COPY => o
            .get_out()
            .and_then(|out| fd.vbank().get(out))
            .is_some_and(|out| out.get_type().get_metatype() == type_metatype::TYPE_FLOAT),
        c => crate::kuna_ptrfromuse::is_float_op(c) && c != OpCode::CPUI_FLOAT_INT2FLOAT,
    }
}

impl Piece {
    /// Plan the access of `size` bytes at `off` inside the variable `vn` is
    /// mapped to; `position` is the address-of-a-position case.
    #[allow(clippy::too_many_arguments)]
    pub fn plan(
        fd: &Funcdata,
        arch: &Architecture,
        vn: VarnodeId,
        op: OpId,
        off: int8,
        size: int4,
        position: bool,
        container: Option<&Datatype>,
    ) -> Option<Piece> {
        let types = arch.types();
        let ptr_size = types.get_size_of_pointer();
        let char_t = types.get_type_char(1).ok()?;
        if position {
            return Some(Piece {
                form: Form::Index(off),
                pointer: types.get_type_pointer(ptr_size, char_t, 1).ok()?,
                bytes: None,
            });
        }
        let own = fd
            .vbank()
            .get(vn)
            .map(|v| Rc::clone(v.get_type()))
            .filter(|t| readable(t, size))
            .filter(|t| t.get_metatype() != type_metatype::TYPE_UNKNOWN || !carries_float(fd, vn, op));
        let value = match own {
            Some(t) => t,
            None if matches!(size, 4 | 8) && carries_float(fd, vn, op) => {
                types.get_base(size, type_metatype::TYPE_FLOAT).ok()?
            }
            None if matches!(size, 1 | 2 | 4 | 8) => types.get_base(size, type_metatype::TYPE_UNKNOWN).ok()?,
            None => {
                let byte = types.get_base(1, type_metatype::TYPE_UNKNOWN).ok()?;
                types.get_type_array(size, byte).ok()?
            }
        };
        let pointer = types.get_type_pointer(ptr_size, value, 1).ok()?;
        let bytes_array = container.is_some_and(|c| {
            c.get_metatype() == type_metatype::TYPE_ARRAY && c.get_array_base().is_some_and(|e| e.get_size() == 1)
        });
        let whole = container.is_some_and(|c| {
            c.get_metatype() == type_metatype::TYPE_ARRAY && c.get_size() == size && !matches!(size, 1 | 2 | 4 | 8)
        });
        let form = if whole && off == 0 {
            Form::Whole
        } else if bytes_array && off == 0 {
            Form::Decay
        } else if bytes_array {
            Form::Element(off)
        } else if off == 0 {
            Form::Base
        } else if off % size as int8 == 0 {
            Form::Index(off / size as int8)
        } else {
            Form::Bytes(off)
        };
        let bytes = match form {
            Form::Bytes(_) => Some(types.get_type_pointer(ptr_size, char_t, 1).ok()?),
            _ => None,
        };
        Some(Piece { form, pointer, bytes })
    }
}
