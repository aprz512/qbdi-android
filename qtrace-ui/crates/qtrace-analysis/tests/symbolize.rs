use std::fs;

use qtrace_analysis::SymbolResolver;
use qtrace_provider::{ArtifactDigest, OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{
    AuthorizedPath, ElfLoadRequest, ElfProducerIdentity, ElfSymbolIndex, LocalSymbolName,
    ModuleIdentity,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn put16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn section(name: u32, kind: u32, offset: u64, size: u64, link: u32, entsize: u64) -> [u8; 64] {
    let mut out = [0; 64];
    put32(&mut out, 0, name);
    put32(&mut out, 4, kind);
    put64(&mut out, 24, offset);
    put64(&mut out, 32, size);
    put32(&mut out, 40, link);
    put64(&mut out, 48, 8);
    put64(&mut out, 56, entsize);
    out
}

fn elf() -> Vec<u8> {
    let shstr = b"\0.shstrtab\0.text\0.strtab\0.symtab\0.note.gnu.build-id\0";
    let strtab = b"\0native_work\0";
    let mut bytes = vec![0; 64];
    let shstr_at = bytes.len();
    bytes.extend_from_slice(shstr);
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let text_at = bytes.len();
    bytes.resize(text_at + 0x100, 0xd5);
    let strtab_at = bytes.len();
    bytes.extend_from_slice(strtab);
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let symtab_at = bytes.len();
    bytes.extend_from_slice(&[0; 24]);
    let mut symbol = [0; 24];
    put32(&mut symbol, 0, 1);
    symbol[4] = 0x12;
    put16(&mut symbol, 6, 2);
    put64(&mut symbol, 8, 0x120);
    put64(&mut symbol, 16, 0x20);
    bytes.extend_from_slice(&symbol);
    let note_at = bytes.len();
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&20_u32.to_le_bytes());
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(b"GNU\0");
    bytes.extend_from_slice(&[0x42; 20]);
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let sections_at = bytes.len();
    bytes.extend_from_slice(&[0; 64]);
    bytes.extend_from_slice(&section(1, 3, shstr_at as u64, shstr.len() as u64, 0, 0));
    let mut text = section(11, 1, text_at as u64, 0x100, 0, 0);
    put64(&mut text, 8, 0x6);
    put64(&mut text, 16, 0x100);
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&section(17, 3, strtab_at as u64, strtab.len() as u64, 0, 0));
    bytes.extend_from_slice(&section(25, 2, symtab_at as u64, 48, 3, 24));
    bytes.extend_from_slice(&section(33, 7, note_at as u64, 36, 0, 0));
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 183);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 40, sections_at as u64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 58, 64);
    put16(&mut bytes, 60, 6);
    put16(&mut bytes, 62, 1);
    bytes
}

#[test]
fn local_name_wins_without_changing_elf_symbol_evidence() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    let bytes = elf();
    fs::write(&path, &bytes).unwrap();
    let module = ModuleIdentity::new(
        "libfixture.so",
        ArtifactDigest::new(Sha256::digest(&bytes).into()),
    );
    let index = ElfSymbolIndex::load(
        ElfLoadRequest::new(
            AuthorizedPath::new(path),
            true,
            module.clone(),
            ElfProducerIdentity::aarch64_android(),
            Some(vec![0x42; 20]),
        ),
        &AllowAll,
    )
    .unwrap();
    let resolver = SymbolResolver::new(
        index,
        vec![LocalSymbolName::new(module.digest(), 0x120, "decrypt_round").unwrap()],
    )
    .unwrap();

    let resolved = resolver.resolve(&module, 0x124).unwrap();
    assert_eq!(resolved.elf_name(), Some("native_work"));
    assert_eq!(resolved.display_name(), "decrypt_round");
    assert_eq!(resolved.relative_address(), 0x120);
    assert_eq!(resolved.offset(), 4);
}

#[test]
fn local_name_for_another_module_never_overrides_display() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("libfixture.so");
    let bytes = elf();
    fs::write(&path, &bytes).unwrap();
    let module = ModuleIdentity::new(
        "libfixture.so",
        ArtifactDigest::new(Sha256::digest(&bytes).into()),
    );
    let index = ElfSymbolIndex::load(
        ElfLoadRequest::new(
            AuthorizedPath::new(path),
            true,
            module.clone(),
            ElfProducerIdentity::aarch64_android(),
            Some(vec![0x42; 20]),
        ),
        &AllowAll,
    )
    .unwrap();
    let resolver = SymbolResolver::new(
        index,
        vec![LocalSymbolName::new(ArtifactDigest::new([9; 32]), 0x120, "wrong").unwrap()],
    )
    .unwrap();
    assert_eq!(
        resolver.resolve(&module, 0x124).unwrap().display_name(),
        "native_work"
    );
    assert!(
        resolver
            .resolve(
                &ModuleIdentity::new("other.so", ArtifactDigest::new([8; 32])),
                0x124
            )
            .is_none()
    );
}
