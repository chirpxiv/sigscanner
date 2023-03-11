// Dependencies

use std::ffi::c_char;

// Modules

pub mod scanning;
pub mod signatures;

// Exports

#[no_mangle]
unsafe extern "C" fn ScanMemory(start_addr: *const u8, size: usize, sig_ptr: *const c_char) -> *const u8 {
	scanning::find_sig_cstr(start_addr, size, sig_ptr)
}