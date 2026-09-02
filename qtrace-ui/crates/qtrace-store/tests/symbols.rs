use std::{
    fs,
    os::unix::fs::symlink,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use qtrace_provider::{ArtifactDigest, OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{
    AuthorizedPath, ElfLoadRequest, ElfProducerIdentity, ElfSymbolIndex, ModuleIdentity,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

struct CancellingProbe {
    work: AtomicU64,
    cancel_after: u64,
    maximum_nodes_delta: AtomicU64,
    maximum_input_delta: AtomicU64,
}

impl WorkGuard for CancellingProbe {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.maximum_nodes_delta
            .fetch_max(delta.nodes, Ordering::Relaxed);
        self.maximum_input_delta
            .fetch_max(delta.input_bytes, Ordering::Relaxed);
        let increment = delta.nodes.saturating_add(delta.input_bytes);
        let before = self.work.fetch_add(increment, Ordering::Relaxed);
        if before.saturating_add(increment) > self.cancel_after {
            return Err(OperationAbort::Cancelled);
        }
        Ok(())
    }
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn align(bytes: &mut Vec<u8>, alignment: usize) {
    bytes.resize(bytes.len().next_multiple_of(alignment), 0);
}

fn symbol(name: u32, value: u64, size: u64) -> [u8; 24] {
    let mut out = [0_u8; 24];
    put32(&mut out, 0, name);
    out[4] = 0x12;
    put16(&mut out, 6, 2);
    put64(&mut out, 8, value);
    put64(&mut out, 16, size);
    out
}

#[allow(clippy::too_many_arguments)]
fn section(
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    alignment: u64,
    entry_size: u64,
) -> [u8; 64] {
    let mut out = [0_u8; 64];
    put32(&mut out, 0, name);
    put32(&mut out, 4, kind);
    put64(&mut out, 8, flags);
    put64(&mut out, 16, address);
    put64(&mut out, 24, offset);
    put64(&mut out, 32, size);
    put32(&mut out, 40, link);
    put64(&mut out, 48, alignment);
    put64(&mut out, 56, entry_size);
    out
}

fn aarch64_elf() -> Vec<u8> {
    aarch64_elf_at(0)
}

fn aarch64_elf_at(image_base: u64) -> Vec<u8> {
    let shstr = b"\0.shstrtab\0.text\0.dynstr\0.dynsym\0.strtab\0.symtab\0.note.gnu.build-id\0";
    let dynstr = b"\0native_work_dyn\0nearest_dyn\0";
    let strtab = b"\0native_work\0next_work\0nearest\0";
    let build_id = [0x42_u8; 20];
    let mut bytes = vec![0_u8; 64 + 56];

    let shstr_offset = bytes.len();
    bytes.extend_from_slice(shstr);
    align(&mut bytes, 16);
    let text_offset = bytes.len();
    bytes.resize(text_offset + 0x200, 0xd5);
    let dynstr_offset = bytes.len();
    bytes.extend_from_slice(dynstr);
    align(&mut bytes, 8);
    let dynsym_offset = bytes.len();
    bytes.extend_from_slice(&[0_u8; 24]);
    bytes.extend_from_slice(&symbol(1, image_base + 0x120, 0x20));
    bytes.extend_from_slice(&symbol(17, image_base + 0x180, 0));
    let strtab_offset = bytes.len();
    bytes.extend_from_slice(strtab);
    align(&mut bytes, 8);
    let symtab_offset = bytes.len();
    bytes.extend_from_slice(&[0_u8; 24]);
    bytes.extend_from_slice(&symbol(1, image_base + 0x120, 0x20));
    bytes.extend_from_slice(&symbol(13, image_base + 0x140, 0x10));
    bytes.extend_from_slice(&symbol(23, image_base + 0x180, 0));
    align(&mut bytes, 4);
    let note_offset = bytes.len();
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&20_u32.to_le_bytes());
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(b"GNU\0");
    bytes.extend_from_slice(&build_id);
    align(&mut bytes, 8);
    let section_offset = bytes.len();

    let names = [0, 1, 11, 17, 25, 33, 41, 49];
    bytes.extend_from_slice(&[0_u8; 64]);
    bytes.extend_from_slice(&section(
        names[1],
        3,
        0,
        0,
        shstr_offset as u64,
        shstr.len() as u64,
        0,
        1,
        0,
    ));
    bytes.extend_from_slice(&section(
        names[2],
        1,
        0x6,
        image_base + 0x100,
        text_offset as u64,
        0x200,
        0,
        16,
        0,
    ));
    bytes.extend_from_slice(&section(
        names[3],
        3,
        0,
        0,
        dynstr_offset as u64,
        dynstr.len() as u64,
        0,
        1,
        0,
    ));
    bytes.extend_from_slice(&section(
        names[4],
        11,
        0,
        0,
        dynsym_offset as u64,
        72,
        3,
        8,
        24,
    ));
    bytes.extend_from_slice(&section(
        names[5],
        3,
        0,
        0,
        strtab_offset as u64,
        strtab.len() as u64,
        0,
        1,
        0,
    ));
    bytes.extend_from_slice(&section(
        names[6],
        2,
        0,
        0,
        symtab_offset as u64,
        96,
        5,
        8,
        24,
    ));
    bytes.extend_from_slice(&section(names[7], 7, 0, 0, note_offset as u64, 36, 0, 4, 0));

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 183);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, 64);
    put64(&mut bytes, 40, section_offset as u64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 1);
    put16(&mut bytes, 58, 64);
    put16(&mut bytes, 60, 8);
    put16(&mut bytes, 62, 1);
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 5);
    put64(&mut bytes, 72, 0);
    put64(&mut bytes, 80, image_base);
    put64(&mut bytes, 88, image_base);
    let file_size = bytes.len() as u64;
    put64(&mut bytes, 96, file_size);
    put64(&mut bytes, 104, file_size);
    put64(&mut bytes, 112, 0x1000);
    bytes
}

fn digest(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::new(Sha256::digest(bytes).into())
}

fn load_request(path: &Path, bytes: &[u8]) -> ElfLoadRequest {
    ElfLoadRequest::new(
        AuthorizedPath::new(path.to_owned()),
        true,
        ModuleIdentity::new("libfixture.so", digest(bytes)),
        ElfProducerIdentity::aarch64_android(),
        Some(vec![0x42; 20]),
    )
}

fn section_data_offset(bytes: &[u8], wanted_kind: u32) -> usize {
    let table = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    (0..count)
        .find_map(|index| {
            let at = table + index * 64;
            let kind = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
            (kind == wanted_kind)
                .then(|| u64::from_le_bytes(bytes[at + 24..at + 32].try_into().unwrap()) as usize)
        })
        .unwrap()
}

fn load_fixture(bytes: Vec<u8>) -> Result<ElfSymbolIndex, qtrace_store::SymbolError> {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    fs::write(&path, &bytes).unwrap();
    ElfSymbolIndex::load(load_request(&path, &bytes), &AllowAll)
}

#[test]
fn loads_only_verified_aarch64_symbols_with_stable_relative_addresses() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    let bytes = aarch64_elf();
    fs::write(&path, &bytes).unwrap();

    let index = ElfSymbolIndex::load(load_request(&path, &bytes), &AllowAll).unwrap();
    assert_eq!(index.build_id(), Some(&[0x42; 20][..]));
    let contained = index.resolve(0x124).unwrap();
    assert_eq!(contained.name(), "native_work");
    assert_eq!(contained.relative_address(), 0x120);
    assert_eq!(contained.offset(), 4);
    let exact_next = index.resolve(0x140).unwrap();
    assert_eq!(exact_next.name(), "next_work");
    assert_eq!(exact_next.offset(), 0);
    let nearest = index.resolve(0x190).unwrap();
    assert_eq!(nearest.name(), "nearest");
    assert_eq!(nearest.offset(), 0x10);

    // The same relative PC resolves independently of any runtime load base.
    assert_eq!(index.resolve(0x124).unwrap(), contained);
}

#[test]
fn normalizes_nonzero_load_image_addresses_to_module_relative_pcs() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    let bytes = aarch64_elf_at(0x40_0000);
    fs::write(&path, &bytes).unwrap();

    let index = ElfSymbolIndex::load(load_request(&path, &bytes), &AllowAll).unwrap();
    let resolved = index.resolve(0x124).unwrap();
    assert_eq!(resolved.name(), "native_work");
    assert_eq!(resolved.relative_address(), 0x120);
    assert_eq!(resolved.offset(), 4);
}

#[test]
fn rejects_unapproved_wrong_identity_and_wrong_build_id() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    let bytes = aarch64_elf();
    fs::write(&path, &bytes).unwrap();

    let unapproved = ElfLoadRequest::new(
        AuthorizedPath::new(path.clone()),
        false,
        ModuleIdentity::new("libfixture.so", digest(&bytes)),
        ElfProducerIdentity::aarch64_android(),
        Some(vec![0x42; 20]),
    );
    assert_eq!(
        ElfSymbolIndex::load(unapproved, &AllowAll)
            .unwrap_err()
            .code(),
        "symbol.approval_required"
    );

    let wrong_producer = ElfLoadRequest::new(
        AuthorizedPath::new(path.clone()),
        true,
        ModuleIdentity::new("libfixture.so", digest(&bytes)),
        ElfProducerIdentity::new(32, true, 40),
        Some(vec![0x42; 20]),
    );
    assert_eq!(
        ElfSymbolIndex::load(wrong_producer, &AllowAll)
            .unwrap_err()
            .code(),
        "symbol.producer_identity_mismatch"
    );

    let wrong_name = ElfLoadRequest::new(
        AuthorizedPath::new(path.clone()),
        true,
        ModuleIdentity::new("other.so", digest(&bytes)),
        ElfProducerIdentity::aarch64_android(),
        Some(vec![0x42; 20]),
    );
    assert_eq!(
        ElfSymbolIndex::load(wrong_name, &AllowAll)
            .unwrap_err()
            .code(),
        "symbol.module_identity_mismatch"
    );

    let wrong_module = ElfLoadRequest::new(
        AuthorizedPath::new(path.clone()),
        true,
        ModuleIdentity::new("libfixture.so", ArtifactDigest::new([9; 32])),
        ElfProducerIdentity::aarch64_android(),
        Some(vec![0x42; 20]),
    );
    assert_eq!(
        ElfSymbolIndex::load(wrong_module, &AllowAll)
            .unwrap_err()
            .code(),
        "symbol.module_identity_mismatch"
    );

    let wrong_build = ElfLoadRequest::new(
        AuthorizedPath::new(path),
        true,
        ModuleIdentity::new("libfixture.so", digest(&bytes)),
        ElfProducerIdentity::aarch64_android(),
        Some(vec![0x99; 20]),
    );
    assert_eq!(
        ElfSymbolIndex::load(wrong_build, &AllowAll)
            .unwrap_err()
            .code(),
        "symbol.build_id_mismatch"
    );
}

#[test]
fn rejects_elf_larger_than_the_loader_bound_before_reading_it() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("huge.so");
    let file = fs::File::create(&path).unwrap();
    file.set_len(512 * 1024 * 1024 + 1).unwrap();
    let request = ElfLoadRequest::new(
        AuthorizedPath::new(path),
        true,
        ModuleIdentity::new("huge.so", ArtifactDigest::new([0; 32])),
        ElfProducerIdentity::aarch64_android(),
        None,
    );
    assert_eq!(
        ElfSymbolIndex::load(request, &AllowAll).unwrap_err().code(),
        "symbol.file_too_large"
    );
}

#[test]
fn rejects_wrong_elf_shape_malformed_bounds_and_symlink_leaf() {
    let temp = TempDir::new().unwrap();
    for (name, mutate, code) in [
        ("elf32.so", (4, 1_u8), "symbol.elf_class_unsupported"),
        ("big.so", (5, 2_u8), "symbol.elf_endian_unsupported"),
        ("x86.so", (18, 62_u8), "symbol.elf_machine_unsupported"),
    ] {
        let mut bytes = aarch64_elf();
        bytes[mutate.0] = mutate.1;
        let path = temp.path().join(name);
        fs::write(&path, &bytes).unwrap();
        let request = ElfLoadRequest::new(
            AuthorizedPath::new(path),
            true,
            ModuleIdentity::new(name, digest(&bytes)),
            ElfProducerIdentity::aarch64_android(),
            None,
        );
        assert_eq!(
            ElfSymbolIndex::load(request, &AllowAll).unwrap_err().code(),
            code
        );
    }

    let mut malformed = aarch64_elf();
    put64(&mut malformed, 40, u64::MAX - 31);
    let malformed_path = temp.path().join("malformed.so");
    fs::write(&malformed_path, &malformed).unwrap();
    assert_eq!(
        ElfSymbolIndex::load(
            ElfLoadRequest::new(
                AuthorizedPath::new(malformed_path),
                true,
                ModuleIdentity::new("malformed.so", digest(&malformed)),
                ElfProducerIdentity::aarch64_android(),
                None,
            ),
            &AllowAll,
        )
        .unwrap_err()
        .code(),
        "symbol.elf_malformed"
    );

    let target = temp.path().join("target.so");
    let link = temp.path().join("libfixture.so");
    let bytes = aarch64_elf();
    fs::write(&target, &bytes).unwrap();
    symlink(&target, &link).unwrap();
    assert_eq!(
        ElfSymbolIndex::load(load_request(&link, &bytes), &AllowAll)
            .unwrap_err()
            .code(),
        "symbol.path_escape"
    );
}

#[test]
fn requires_loadable_executable_images_and_filters_non_text_symbols() {
    let mut relocatable = aarch64_elf();
    put16(&mut relocatable, 16, 1);
    assert_eq!(
        load_fixture(relocatable).unwrap_err().code(),
        "symbol.elf_type_unsupported"
    );

    let mut without_load = aarch64_elf();
    put16(&mut without_load, 56, 0);
    assert_eq!(
        load_fixture(without_load).unwrap_err().code(),
        "symbol.elf_segment_invalid"
    );

    let mut overflowing_load = aarch64_elf();
    put64(&mut overflowing_load, 80, u64::MAX - 0x100);
    put64(&mut overflowing_load, 88, u64::MAX - 0x100);
    put64(&mut overflowing_load, 104, 0x200);
    assert_eq!(
        load_fixture(overflowing_load).unwrap_err().code(),
        "symbol.elf_segment_invalid"
    );

    let mut outside_load = aarch64_elf();
    put64(&mut outside_load, 80, 0x100);
    put64(&mut outside_load, 88, 0x100);
    put64(&mut outside_load, 96, 0x30);
    put64(&mut outside_load, 104, 0x30);
    let outside = load_fixture(outside_load).unwrap();
    assert!(outside.resolve(0x120).is_none());
    assert!(outside.resolve(0x180).is_none());

    for symbol_kind in [1_u8, 6_u8] {
        let mut non_text = aarch64_elf();
        for section_kind in [11_u32, 2_u32] {
            let table = section_data_offset(&non_text, section_kind);
            non_text[table + 24 + 4] = 0x10 | symbol_kind;
        }
        let index = load_fixture(non_text).unwrap();
        assert!(
            index.resolve(0x120).is_none(),
            "accepted ELF symbol kind {symbol_kind}"
        );
    }
}

#[test]
fn hashing_parsing_and_skipped_entries_observe_chunked_cancellation() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    let mut bytes = aarch64_elf();
    bytes.resize(1024 * 1024, 0);
    fs::write(&path, &bytes).unwrap();
    for cancel_after in [32 * 1024, bytes.len() as u64 * 2 + 20] {
        let guard = CancellingProbe {
            work: AtomicU64::new(0),
            cancel_after,
            maximum_nodes_delta: AtomicU64::new(0),
            maximum_input_delta: AtomicU64::new(0),
        };
        let error = ElfSymbolIndex::load(load_request(&path, &bytes), &guard).unwrap_err();
        assert_eq!(error.code(), "job.cancelled");
        assert!(guard.maximum_nodes_delta.load(Ordering::Relaxed) <= 4096);
        assert!(guard.maximum_input_delta.load(Ordering::Relaxed) <= 4096);
    }
}
