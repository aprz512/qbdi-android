#![no_main]
use libfuzzer_sys::fuzz_target;
mod storage_support;
mod support;
fuzz_target!(|data: &[u8]| {
    storage_support::fuzz_annotations(data);
});
