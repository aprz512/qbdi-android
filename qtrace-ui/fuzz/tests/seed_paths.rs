#[path = "../fuzz_targets/support.rs"]
mod support;

const STANDARD_MAGIC: &[u8] = &[0x04, 0x22, 0x4d, 0x18];

#[derive(Debug)]
struct FrameShape {
    linked: bool,
    blocks: usize,
    next: usize,
}

fn frame_shape(bytes: &[u8], start: usize) -> FrameShape {
    assert_eq!(bytes.get(start..start + 4), Some(STANDARD_MAGIC));
    let flags = bytes[start + 4];
    let mut cursor = start + 6;
    if flags & 0x08 != 0 {
        cursor += 8;
    }
    if flags & 0x01 != 0 {
        cursor += 4;
    }
    cursor += 1;
    let mut blocks = 0;
    loop {
        let size = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        if size == 0 {
            break;
        }
        cursor += (size & 0x7fff_ffff) as usize;
        if flags & 0x10 != 0 {
            cursor += 4;
        }
        blocks += 1;
    }
    if flags & 0x04 != 0 {
        cursor += 4;
    }
    FrameShape {
        linked: flags & 0x20 == 0,
        blocks,
        next: cursor,
    }
}

#[test]
fn compressed_qtrb_selectors_expand_and_fully_drain() {
    for (selector, expected_frames, expected_linked, minimum_blocks) in [
        (&b"qtrb-lz4:standard\n"[..], 1, false, 1),
        (&b"qtrb-lz4:linked-blocks\n"[..], 1, true, 2),
        (&b"qtrb-lz4:concatenated-frames\n"[..], 2, false, 2),
    ] {
        let expanded = support::expand_qtrb_seed(selector);
        assert_eq!(expanded.get(..4), Some(STANDARD_MAGIC), "{selector:?}");
        assert!(
            support::qtrb_lz4_seed_fully_drains(selector),
            "{selector:?}"
        );
        let mut cursor = 0;
        let mut frames = Vec::new();
        while cursor < expanded.len() {
            let shape = frame_shape(&expanded, cursor);
            cursor = shape.next;
            frames.push(shape);
        }
        assert_eq!(frames.len(), expected_frames, "{selector:?}: {frames:?}");
        assert_eq!(
            frames.iter().any(|frame| frame.linked),
            expected_linked,
            "{selector:?}: {frames:?}"
        );
        assert!(
            frames.iter().map(|frame| frame.blocks).sum::<usize>() >= minimum_blocks,
            "{selector:?}: {frames:?}"
        );
    }
}
