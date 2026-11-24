//! H.264 / HEVC Annex B bitstream helpers (start-code delimited NAL units).

use crate::wire::Codec;
use memchr::memmem;

/// Iterate NAL units (without start codes) of an Annex B buffer.
pub fn nal_units(data: &[u8]) -> NalIter<'_> {
    NalIter { data, pos: first_start(data, 0) }
}

/// Offset just past the first `00 00 01` at or after `from`.
fn first_start(data: &[u8], from: usize) -> Option<usize> {
    memmem::find(&data[from..], &[0, 0, 1]).map(|i| from + i + 3)
}

pub struct NalIter<'a> {
    data: &'a [u8],
    pos: Option<usize>,
}

impl<'a> Iterator for NalIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            let start = self.pos?;
            let (mut end, next) = match memmem::find(&self.data[start..], &[0, 0, 1]) {
                Some(i) => (start + i, Some(start + i + 3)),
                None => (self.data.len(), None),
            };
            self.pos = next;
            // Zero bytes before a start code belong to it (4-byte codes / trailing_zero_8bits).
            while end > start && self.data[end - 1] == 0 {
                end -= 1;
            }
            if end > start {
                return Some(&self.data[start..end]);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NalKind {
    /// Slice of an IDR / IRAP picture.
    KeySlice,
    Slice,
    Vps,
    Sps,
    Pps,
    Aud,
    Other,
}

pub fn nal_kind(codec: Codec, nal: &[u8]) -> NalKind {
    let Some(&b0) = nal.first() else { return NalKind::Other };
    match codec {
        Codec::H264 => match b0 & 0x1f {
            5 => NalKind::KeySlice,
            1..=4 => NalKind::Slice,
            7 => NalKind::Sps,
            8 => NalKind::Pps,
            9 => NalKind::Aud,
            _ => NalKind::Other,
        },
        Codec::Hevc => match (b0 >> 1) & 0x3f {
            16..=23 => NalKind::KeySlice,
            0..=9 => NalKind::Slice,
            32 => NalKind::Vps,
            33 => NalKind::Sps,
            34 => NalKind::Pps,
            35 => NalKind::Aud,
            _ => NalKind::Other,
        },
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuInfo {
    pub keyframe: bool,
    pub has_param_sets: bool,
    pub has_aud: bool,
    pub slices: u32,
}

/// Classify one access unit.
pub fn inspect(codec: Codec, au: &[u8]) -> AuInfo {
    let mut info = AuInfo::default();
    for nal in nal_units(au) {
        match nal_kind(codec, nal) {
            NalKind::KeySlice => {
                info.keyframe = true;
                info.slices += 1;
            }
            NalKind::Slice => info.slices += 1,
            NalKind::Sps => info.has_param_sets = true,
            NalKind::Aud => info.has_aud = true,
            _ => {}
        }
    }
    info
}

/// Access unit delimiter NAL (with start code) for the codec.
pub fn aud(codec: Codec) -> &'static [u8] {
    match codec {
        Codec::H264 => &[0, 0, 0, 1, 0x09, 0xf0],
        Codec::Hevc => &[0, 0, 0, 1, 0x46, 0x01, 0x50],
    }
}

/// Parameter sets extracted from a keyframe access unit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParamSets {
    pub vps: Vec<u8>,
    pub sps: Vec<u8>,
    pub pps: Vec<u8>,
}

impl ParamSets {
    pub fn complete(&self, codec: Codec) -> bool {
        !self.sps.is_empty() && !self.pps.is_empty() && (codec == Codec::H264 || !self.vps.is_empty())
    }
}

pub fn param_sets(codec: Codec, au: &[u8]) -> ParamSets {
    let mut ps = ParamSets::default();
    for nal in nal_units(au) {
        match nal_kind(codec, nal) {
            NalKind::Vps if ps.vps.is_empty() => ps.vps = nal.to_vec(),
            NalKind::Sps if ps.sps.is_empty() => ps.sps = nal.to_vec(),
            NalKind::Pps if ps.pps.is_empty() => ps.pps = nal.to_vec(),
            NalKind::KeySlice | NalKind::Slice => break,
            _ => {}
        }
    }
    ps
}

/// Rewrite an access unit as 4-byte-length-prefixed NALs (AVCC/HVCC sample
/// layout), keeping only slice data: parameter sets live in the format
/// description and AUDs are noise for the decoder.
pub fn to_length_prefixed(codec: Codec, au: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(au.len() + 16);
    for nal in nal_units(au) {
        match nal_kind(codec, nal) {
            NalKind::Vps | NalKind::Sps | NalKind::Pps | NalKind::Aud => continue,
            _ => {}
        }
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(nal);
    }
}

/// Guess the codec of an Annex B elementary stream from its first NALs.
pub fn sniff_codec(data: &[u8]) -> Option<Codec> {
    for nal in nal_units(data).take(8) {
        let b0 = nal[0];
        // HEVC VPS/SPS/AUD have a two-byte header with nuh_layer_id = 0, tid = 1.
        if nal.len() >= 2 && nal[1] == 1 && matches!((b0 >> 1) & 0x3f, 32 | 33 | 35) && b0 & 0x81 == 0 {
            return Some(Codec::Hevc);
        }
        if matches!(b0 & 0x1f, 7 | 9) && b0 & 0x80 == 0 {
            return Some(Codec::H264);
        }
    }
    None
}

/// Split an elementary stream into access units.
///
/// Boundaries are AUD NALs when the stream has them; otherwise a new access
/// unit starts at each parameter set / slice with `first_mb_in_slice == 0`
/// (resp. `first_slice_segment_in_pic_flag`) that follows a slice.
pub fn split_access_units(codec: Codec, data: &[u8]) -> Vec<&[u8]> {
    let base = data.as_ptr() as usize;
    let mut units = Vec::new();
    let mut au_start: Option<usize> = None;
    let mut seen_slice = false;
    for nal in nal_units(data) {
        let off = nal.as_ptr() as usize - base;
        // Start code begins 3 bytes back, 4 if preceded by another zero.
        let mut sc = off - 3;
        if sc > 0 && data[sc - 1] == 0 {
            sc -= 1;
        }
        let kind = nal_kind(codec, nal);
        let first_slice_of_picture = match (codec, kind) {
            (Codec::H264, NalKind::Slice | NalKind::KeySlice) => nal.len() > 1 && nal[1] & 0x80 != 0,
            (Codec::Hevc, NalKind::Slice | NalKind::KeySlice) => nal.len() > 2 && nal[2] & 0x80 != 0,
            _ => false,
        };
        let boundary = match kind {
            NalKind::Aud => true,
            NalKind::Vps | NalKind::Sps | NalKind::Pps | NalKind::Other => seen_slice,
            NalKind::Slice | NalKind::KeySlice => seen_slice && first_slice_of_picture,
        };
        if boundary || au_start.is_none() {
            if let Some(s) = au_start {
                if seen_slice {
                    units.push(&data[s..sc]);
                    au_start = Some(sc);
                    seen_slice = false;
                }
            } else {
                au_start = Some(sc);
            }
        }
        if matches!(kind, NalKind::Slice | NalKind::KeySlice) {
            seen_slice = true;
        }
    }
    if let Some(s) = au_start {
        if seen_slice {
            units.push(&data[s..]);
        }
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPS: &[u8] = &[0x67, 0x42, 0x00, 0x1f];
    const PPS: &[u8] = &[0x68, 0xce, 0x3c, 0x80];
    const IDR: &[u8] = &[0x65, 0x88, 0x84, 0x00, 0x10];
    const P: &[u8] = &[0x41, 0x9a, 0x24, 0x6c];
    const P_CONT: &[u8] = &[0x41, 0x1a, 0x24, 0x6c]; // first_mb != 0

    fn annexb(nals: &[&[u8]], four: bool) -> Vec<u8> {
        let mut v = Vec::new();
        for n in nals {
            if four {
                v.push(0);
            }
            v.extend_from_slice(&[0, 0, 1]);
            v.extend_from_slice(n);
        }
        v
    }

    #[test]
    fn iterates_3_and_4_byte_start_codes() {
        for four in [false, true] {
            let buf = annexb(&[SPS, PPS, IDR], four);
            let nals: Vec<&[u8]> = nal_units(&buf).collect();
            assert_eq!(nals, vec![SPS, PPS, IDR]);
        }
        assert_eq!(nal_units(&[1, 2, 3]).count(), 0);
        assert_eq!(nal_units(&[]).count(), 0);
    }

    #[test]
    fn inspect_and_param_sets() {
        let key = annexb(&[&[0x09, 0xf0], SPS, PPS, IDR], true);
        let info = inspect(Codec::H264, &key);
        assert!(info.keyframe && info.has_param_sets && info.has_aud);
        let ps = param_sets(Codec::H264, &key);
        assert_eq!((ps.sps.as_slice(), ps.pps.as_slice()), (SPS, PPS));
        assert!(ps.complete(Codec::H264));
        let p = annexb(&[P], true);
        assert_eq!(inspect(Codec::H264, &p), AuInfo { keyframe: false, has_param_sets: false, has_aud: false, slices: 1 });
    }

    #[test]
    fn length_prefix_conversion_drops_non_vcl() {
        let key = annexb(&[&[0x09, 0xf0], SPS, PPS, IDR, P_CONT], false);
        let mut out = Vec::new();
        to_length_prefixed(Codec::H264, &key, &mut out);
        let mut expect = Vec::new();
        expect.extend_from_slice(&(IDR.len() as u32).to_be_bytes());
        expect.extend_from_slice(IDR);
        expect.extend_from_slice(&(P_CONT.len() as u32).to_be_bytes());
        expect.extend_from_slice(P_CONT);
        assert_eq!(out, expect);
    }

    #[test]
    fn splits_access_units_with_and_without_aud() {
        let aud: &[u8] = &[0x09, 0xf0];
        let with = annexb(&[aud, SPS, PPS, IDR, aud, P, P_CONT, aud, P], true);
        let aus = split_access_units(Codec::H264, &with);
        assert_eq!(aus.len(), 3);
        assert_eq!(aus[0], &annexb(&[aud, SPS, PPS, IDR], true)[..]);
        assert_eq!(aus[1], &annexb(&[aud, P, P_CONT], true)[..]);
        assert_eq!(aus.concat(), with);

        let without = annexb(&[SPS, PPS, IDR, P, P_CONT, P, SPS, PPS, IDR], true);
        let aus = split_access_units(Codec::H264, &without);
        assert_eq!(aus.len(), 4);
        assert_eq!(aus[1], &annexb(&[P, P_CONT], true)[..]);
        assert_eq!(aus[3], &annexb(&[SPS, PPS, IDR], true)[..]);
        assert_eq!(aus.concat(), without);
    }

    #[test]
    fn hevc_kinds() {
        assert_eq!(nal_kind(Codec::Hevc, &[0x40, 0x01]), NalKind::Vps);
        assert_eq!(nal_kind(Codec::Hevc, &[0x42, 0x01]), NalKind::Sps);
        assert_eq!(nal_kind(Codec::Hevc, &[0x44, 0x01]), NalKind::Pps);
        assert_eq!(nal_kind(Codec::Hevc, &[0x46, 0x01]), NalKind::Aud);
        assert_eq!(nal_kind(Codec::Hevc, &[0x26, 0x01]), NalKind::KeySlice); // IDR_W_RADL
        assert_eq!(nal_kind(Codec::Hevc, &[0x02, 0x01]), NalKind::Slice); // TRAIL_R
        assert_eq!(sniff_codec(&annexb(&[&[0x40, 0x01, 0x0c]], true)), Some(Codec::Hevc));
        assert_eq!(sniff_codec(&annexb(&[SPS], true)), Some(Codec::H264));
    }
}
