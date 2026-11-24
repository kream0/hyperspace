//! Cursor shape messages (host -> client) and conversion of Windows pointer
//! bitmaps into straight-alpha RGBA.

/// A cursor image, RGBA8 with straight alpha, rows top-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub rgba: Vec<u8>,
}

pub const MAX_CURSOR_DIM: u16 = 512;

impl CursorShape {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + self.rgba.len());
        v.extend_from_slice(&self.width.to_le_bytes());
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.hot_x.to_le_bytes());
        v.extend_from_slice(&self.hot_y.to_le_bytes());
        v.extend_from_slice(&self.rgba);
        v
    }

    pub fn decode(b: &[u8]) -> Option<CursorShape> {
        if b.len() < 8 {
            return None;
        }
        let g = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let (width, height) = (g(0), g(2));
        if width == 0 || height == 0 || width > MAX_CURSOR_DIM || height > MAX_CURSOR_DIM {
            return None;
        }
        if b.len() - 8 != width as usize * height as usize * 4 {
            return None;
        }
        Some(CursorShape { width, height, hot_x: g(4), hot_y: g(6), rgba: b[8..].to_vec() })
    }

    /// 32bpp BGRA with alpha (DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR).
    pub fn from_bgra(width: u32, height: u32, pitch: usize, hot: (u32, u32), data: &[u8]) -> Option<CursorShape> {
        let (w, h) = check_dims(width, height)?;
        if pitch < w * 4 || data.len() < pitch * (h - 1) + w * 4 {
            return None;
        }
        let mut rgba = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for px in data[y * pitch..y * pitch + w * 4].chunks_exact(4) {
                rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
            }
        }
        Some(Self::finish(w, h, hot, rgba))
    }

    /// 32bpp BGRA whose alpha byte is a mask: 0 = replace, 0xFF = XOR with the
    /// screen (DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR).
    pub fn from_masked_color(width: u32, height: u32, pitch: usize, hot: (u32, u32), data: &[u8]) -> Option<CursorShape> {
        let (w, h) = check_dims(width, height)?;
        if pitch < w * 4 || data.len() < pitch * (h - 1) + w * 4 {
            return None;
        }
        let mut rgba = Vec::with_capacity(w * h * 4);
        let mut invert = vec![false; w * h];
        for y in 0..h {
            for (x, px) in data[y * pitch..y * pitch + w * 4].chunks_exact(4).enumerate() {
                let (b, g, r, mask) = (px[0], px[1], px[2], px[3]);
                if mask == 0 {
                    rgba.extend_from_slice(&[r, g, b, 255]);
                } else if r | g | b == 0 {
                    rgba.extend_from_slice(&[0, 0, 0, 0]);
                } else {
                    invert[y * w + x] = true;
                    rgba.extend_from_slice(&[0, 0, 0, 255]);
                }
            }
        }
        outline_inverted(w, h, &invert, &mut rgba);
        Some(Self::finish(w, h, hot, rgba))
    }

    /// 1bpp AND mask stacked on a 1bpp XOR mask; `height` covers both
    /// (DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME).
    pub fn from_monochrome(width: u32, height: u32, pitch: usize, hot: (u32, u32), data: &[u8]) -> Option<CursorShape> {
        let (w, h) = check_dims(width, height / 2)?;
        if pitch * 8 < w || data.len() < pitch * h * 2 {
            return None;
        }
        let bit = |row: usize, x: usize| data[row * pitch + x / 8] & (0x80 >> (x % 8)) != 0;
        let mut rgba = Vec::with_capacity(w * h * 4);
        let mut invert = vec![false; w * h];
        for y in 0..h {
            for x in 0..w {
                let px: [u8; 4] = match (bit(y, x), bit(y + h, x)) {
                    (false, false) => [0, 0, 0, 255],
                    (false, true) => [255, 255, 255, 255],
                    (true, false) => [0, 0, 0, 0],
                    (true, true) => {
                        invert[y * w + x] = true;
                        [0, 0, 0, 255]
                    }
                };
                rgba.extend_from_slice(&px);
            }
        }
        outline_inverted(w, h, &invert, &mut rgba);
        Some(Self::finish(w, h, hot, rgba))
    }

    fn finish(w: usize, h: usize, hot: (u32, u32), rgba: Vec<u8>) -> CursorShape {
        CursorShape {
            width: w as u16,
            height: h as u16,
            hot_x: hot.0.min(w as u32 - 1) as u16,
            hot_y: hot.1.min(h as u32 - 1) as u16,
            rgba,
        }
    }
}

fn check_dims(width: u32, height: u32) -> Option<(usize, usize)> {
    if width == 0 || height == 0 || width > MAX_CURSOR_DIM as u32 || height > MAX_CURSOR_DIM as u32 {
        return None;
    }
    Some((width as usize, height as usize))
}

/// "Invert the screen" pixels cannot be reproduced by a client-side cursor.
/// They are drawn black; give them a white rim so e.g. the I-beam stays
/// visible on dark backgrounds.
fn outline_inverted(w: usize, h: usize, invert: &[bool], rgba: &mut [u8]) {
    for y in 0..h {
        for x in 0..w {
            if !invert[y * w + x] {
                continue;
            }
            for (dx, dy) in [(-1i32, 0i32), (1, 0), (0, -1), (0, 1)] {
                let (nx, ny) = (x as i32 + dx, y as i32 + dy);
                if nx < 0 || ny < 0 || nx >= w as i32 || ny >= h as i32 {
                    continue;
                }
                let i = (ny as usize * w + nx as usize) * 4;
                if rgba[i + 3] == 0 {
                    rgba[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let c = CursorShape { width: 2, height: 1, hot_x: 1, hot_y: 0, rgba: vec![1, 2, 3, 4, 5, 6, 7, 8] };
        assert_eq!(CursorShape::decode(&c.encode()), Some(c));
        assert_eq!(CursorShape::decode(&[0; 8]), None);
        assert_eq!(CursorShape::decode(&[2, 0, 1, 0, 0, 0, 0, 0, 1, 2, 3]), None);
    }

    #[test]
    fn bgra_swaps_channels_and_honours_pitch() {
        // 1x2, pitch 8 (4 bytes padding per row)
        let data = [10, 20, 30, 40, 0, 0, 0, 0, 50, 60, 70, 80, 0, 0, 0, 0];
        let c = CursorShape::from_bgra(1, 2, 8, (0, 5), &data).unwrap();
        assert_eq!(c.rgba, vec![30, 20, 10, 40, 70, 60, 50, 80]);
        assert_eq!(c.hot_y, 1); // clamped
    }

    #[test]
    fn monochrome_pixels() {
        // 8x1 cursor: AND row then XOR row, pitch 1.
        // x0: and0 xor0 black; x1: and0 xor1 white; x2: and1 xor0 transparent; x3: and1 xor1 invert
        let and = 0b0011_1111u8 | 0b0000_0000;
        let xor = 0b0101_0000u8;
        let c = CursorShape::from_monochrome(8, 2, 1, (0, 0), &[and, xor]).unwrap();
        let px = |x: usize| &c.rgba[x * 4..x * 4 + 4];
        assert_eq!(px(0), [0, 0, 0, 255]);
        assert_eq!(px(1), [255, 255, 255, 255]);
        assert_eq!(px(3), [0, 0, 0, 255]); // inverted -> black
        assert_eq!(px(2), [255, 255, 255, 255]); // transparent neighbour of inverted -> white rim
        assert_eq!(px(4), [255, 255, 255, 255]);
        assert_eq!(px(5), [0, 0, 0, 0]);
    }

    #[test]
    fn masked_color_pixels() {
        let data = [
            1, 2, 3, 0, // replace
            0, 0, 0, 255, // transparent
            9, 9, 9, 255, // xor -> black
        ];
        let c = CursorShape::from_masked_color(3, 1, 12, (0, 0), &data).unwrap();
        assert_eq!(&c.rgba[0..4], [3, 2, 1, 255]);
        assert_eq!(&c.rgba[4..8], [255, 255, 255, 255]); // rim next to inverted pixel
        assert_eq!(&c.rgba[8..12], [0, 0, 0, 255]);
    }
}
