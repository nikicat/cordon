//! Compile-time layout checks for the POD types that BPF maps copy byte for byte, and the
//! [`padded_pod!`] macro that applies them.
//!
//! aya writes a map value by handing a `&[u8]` view of it to `bpf_map_update_elem`. Two
//! things must hold for that copy to be sound and stable:
//!  - The value is fully initialized. A byte view over uninitialized padding is UB. For a
//!    map key, BPF also hashes and compares the whole byte span, so stray padding bytes
//!    would split one logical key across buckets.
//!  - The value is deterministic. The same logical value produces the same bytes, with no
//!    stack garbage in the gaps, so an in-map image is reproducible.
//!
//! [`padded_pod!`] gives both. It appends a trailing `_pad` that is sized automatically and
//! always zeroed, which rounds the struct up to its alignment. It also asserts at compile
//! time that the struct has no interior padding, which a trailing pad cannot fill, so a
//! field reorder that opens an interior gap fails the build rather than a test. Field order
//! stays the author's choice, and laying fields out from large to small keeps them
//! gap-free.

/// Returns the size and alignment of `T`, as one entry of the list that [`trailing_pad`]
/// takes. It is a `const fn` because type sizes are known only at compile time, and a
/// proc-macro working on tokens could not see them.
pub(crate) const fn field<T>() -> (usize, usize) {
    (core::mem::size_of::<T>(), core::mem::align_of::<T>())
}

/// Returns `n` rounded up to the next multiple of `align`, which is a power of two.
const fn round_up(n: usize, align: usize) -> usize {
    n.div_ceil(align) * align
}

/// Returns the number of trailing pad bytes that a `#[repr(C)]` struct with these
/// `(size, align)` fields needs to round its size up to its own alignment, following the
/// `repr(C)` layout rules. It counts only the trailing gap, because the [`padded_pod!`]
/// assertion rejects any interior one.
pub(crate) const fn trailing_pad(fields: &[(usize, usize)]) -> usize {
    let mut off = 0;
    let mut max_align = 1;
    let mut i = 0;
    while i < fields.len() {
        let (size, align) = fields[i];
        off = round_up(off, align) + size;
        if align > max_align {
            max_align = align;
        }
        i += 1;
    }
    round_up(off, max_align) - off
}

/// Declares a `#[repr(C)]` POD struct with a zeroed trailing `_pad` of the right size, and
/// fails the build if the struct has interior padding. The module docs say why both matter.
///
/// The appended field is `_pad: [u8; Self::PAD]`, and a constructor sets it to
/// `[0; Self::PAD]`. The same pattern works when `PAD` is 0, since `[0; 0]` is an empty
/// array. Attributes such as `#[repr(C)]` and `#[derive(…)]`, and per-field doc comments,
/// pass through as usual. The derives apply to `_pad` too, since `[u8; N]` is `Copy`, `Eq`,
/// `Hash` and so on.
macro_rules! padded_pod {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$fmeta:meta])*
                $fvis:vis $fname:ident : $fty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(
                $(#[$fmeta])*
                $fvis $fname: $fty,
            )*
            /// Zeroed trailing padding that `padded_pod!` generated (the `layout` module
            /// docs say why). Constructors set it to `[0; Self::PAD]`, and the kernel never
            /// reads it.
            $vis _pad: [u8; $name::PAD],
        }

        impl $name {
            /// The length of the generated trailing [`_pad`](Self::_pad), computed from the
            /// sizes and alignments of the field types.
            $vis const PAD: usize =
                $crate::layout::trailing_pad(&[$( $crate::layout::field::<$fty>() ),*]);
        }

        // The trailing pad rounds the size up to the alignment but cannot fill an interior
        // gap. This assertion proves there is none, so a reorder that opens one fails the
        // build here.
        const _: () = assert!(
            ::core::mem::size_of::<$name>()
                == (0 $( + ::core::mem::size_of::<$fty>() )*) + $name::PAD,
            concat!(
                stringify!($name),
                ": interior padding — reorder fields (large-to-small) so the type is packed"
            ),
        );
    };
}
