//! CPU colour conversion for the software-encoder fallback path.

/// Convert BGRA rows (`pitch` bytes apart) to NV12 using BT.709 limited range,
/// matching what the GPU video processor produces. `width`/`height` must be
/// even; `dst` is resized to `width * height * 3 / 2`.
pub fn bgra_to_nv12(src: &[u8], pitch: usize, width: usize, height: usize, dst: &mut Vec<u8>) {
    assert!(width.is_multiple_of(2) && height.is_multiple_of(2) && pitch >= width * 4);
    assert!(src.len() >= pitch * (height - 1) + width * 4);
    dst.resize(width * height * 3 / 2, 0);
    let (y_plane, uv_plane) = dst.split_at_mut(width * height);

    #[inline(always)]
    fn luma(b: u32, g: u32, r: u32) -> u8 {
        (((47 * r + 157 * g + 16 * b + 128) >> 8) + 16) as u8
    }

    for (row2, (y_rows, uv_row)) in y_plane.chunks_exact_mut(width * 2).zip(uv_plane.chunks_exact_mut(width)).enumerate() {
        let s0 = &src[row2 * 2 * pitch..row2 * 2 * pitch + width * 4];
        let s1 = &src[(row2 * 2 + 1) * pitch..(row2 * 2 + 1) * pitch + width * 4];
        let (y0, y1) = y_rows.split_at_mut(width);
        for (((p0, p1), (ya, yb)), uv) in s0
            .chunks_exact(8)
            .zip(s1.chunks_exact(8))
            .zip(y0.chunks_exact_mut(2).zip(y1.chunks_exact_mut(2)))
            .zip(uv_row.chunks_exact_mut(2))
        {
            let px = |p: &[u8], i: usize| (p[i * 4] as u32, p[i * 4 + 1] as u32, p[i * 4 + 2] as u32);
            let (b00, g00, r00) = px(p0, 0);
            let (b01, g01, r01) = px(p0, 1);
            let (b10, g10, r10) = px(p1, 0);
            let (b11, g11, r11) = px(p1, 1);
            ya[0] = luma(b00, g00, r00);
            ya[1] = luma(b01, g01, r01);
            yb[0] = luma(b10, g10, r10);
            yb[1] = luma(b11, g11, r11);
            let b = ((b00 + b01 + b10 + b11 + 2) >> 2) as i32;
            let g = ((g00 + g01 + g10 + g11 + 2) >> 2) as i32;
            let r = ((r00 + r01 + r10 + r11 + 2) >> 2) as i32;
            uv[0] = (((-26 * r - 86 * g + 112 * b + 128) >> 8) + 128) as u8;
            uv[1] = (((112 * r - 102 * g - 10 * b + 128) >> 8) + 128) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert_solid(b: u8, g: u8, r: u8) -> (u8, u8, u8) {
        let (w, h, pitch) = (4usize, 2usize, 20usize);
        let mut src = vec![0u8; pitch * h];
        for y in 0..h {
            for x in 0..w {
                src[y * pitch + x * 4..y * pitch + x * 4 + 4].copy_from_slice(&[b, g, r, 255]);
            }
        }
        let mut dst = Vec::new();
        bgra_to_nv12(&src, pitch, w, h, &mut dst);
        assert_eq!(dst.len(), w * h * 3 / 2);
        assert!(dst[..w * h].iter().all(|&y| y == dst[0]));
        (dst[0], dst[w * h], dst[w * h + 1])
    }

    #[test]
    fn bt709_limited_reference_points() {
        assert_eq!(convert_solid(0, 0, 0), (16, 128, 128));
        assert_eq!(convert_solid(255, 255, 255), (235, 128, 128));
        // pure red: Y=63 Cb=102 Cr=240 (within rounding)
        let (y, u, v) = convert_solid(0, 0, 255);
        assert!((y as i32 - 63).abs() <= 1 && (u as i32 - 102).abs() <= 1 && (v as i32 - 240).abs() <= 1, "{y} {u} {v}");
        // pure blue: Y=32 Cb=240 Cr=118
        let (y, u, v) = convert_solid(255, 0, 0);
        assert!((y as i32 - 32).abs() <= 1 && (u as i32 - 240).abs() <= 1 && (v as i32 - 118).abs() <= 1, "{y} {u} {v}");
    }
}
