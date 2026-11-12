//! Helpers which consume untrusted lengths and count fields
//!
//! Every parser reads sizes from untrusted bytes. These helpers exist so
//! that no parser ever passes a wire-supplied integer directly to
//! `Vec::with_capacity`, a slice index, or a recursion depth without first
//! clamping it to something the available input could plausibly satisfy.

use std::num::NonZeroUsize;

/// Hard ceiling on elements pre-allocated from a wire count, regardless of
/// input length. `Vec` will grow past this if the data is actually present.
pub const MAX_PREALLOC: usize = 1024;

/// Hard ceiling on recursive descent into nested wire structures.
pub const MAX_RECURSION_DEPTH: u8 = 64;

/// Clamp an untrusted element count to a safe pre-allocation size.
///
/// The result never exceeds the number of minimum-size elements that could
/// fit in the remaining input, nor [`MAX_PREALLOC`]. Use this for the capacity
/// hint only — still loop on `count` (or until input is exhausted) so that a
/// well-formed message with more than `MAX_PREALLOC` elements parses fully.
#[inline]
pub fn bounded_capacity(
    count: usize,
    remaining_input: usize,
    min_elem_size: NonZeroUsize,
) -> usize {
    let by_input = remaining_input / min_elem_size;
    count.min(by_input).min(MAX_PREALLOC)
}

/// Subtract `b` from `a`, mapping underflow to a nom `LengthValue` error.
///
/// Use when a wire length field includes its own header
/// (e.g. `payload_len = total_len - HEADER`) and `total_len < HEADER` is
/// untrusted wire data.
#[inline]
pub fn checked_sub_or_err<I>(a: usize, b: usize, input: I) -> nom::IResult<I, usize>
where
    I: Clone,
{
    a.checked_sub(b).map(|v| (input.clone(), v)).ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::LengthValue,
        ))
    })
}

/// Recursion-depth guard. Construct at the public entry point and pass
/// `guard.descend()?` into each recursive call.
#[derive(Clone, Copy, Debug)]
pub struct DepthGuard(u8);

impl Default for DepthGuard {
    fn default() -> Self {
        Self(MAX_RECURSION_DEPTH)
    }
}

impl DepthGuard {
    pub fn new(max: u8) -> Self {
        Self(max)
    }

    /// Consume one level of depth. Returns `None` when the limit is reached;
    /// callers should treat that as malformed/looping input.
    #[inline]
    pub fn descend(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn capacity_bounded_by_input() {
        assert_eq!(
            bounded_capacity(1_000_000, 40, NonZeroUsize::try_from(4usize).unwrap()),
            10
        );
    }

    #[test]
    fn capacity_bounded_by_ceiling() {
        assert_eq!(
            bounded_capacity(1_000_000, 1_000_000, NonZeroUsize::try_from(1).unwrap()),
            MAX_PREALLOC
        );
    }

    #[test]
    fn depth_guard_exhausts() {
        let mut g = DepthGuard::new(2);
        g = g.descend().unwrap();
        g = g.descend().unwrap();
        assert!(g.descend().is_none());
    }
}
