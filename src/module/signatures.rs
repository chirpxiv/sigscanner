// Dependencies

use std::ffi::{CStr, c_char};

// Parse sig string (ie. "E8 ?? ?? ?? ?? 8A 5F 28")

pub fn parse_sig_str(sig: &str) -> Vec<Option<u8>> {
	let split: Vec<&str> = sig.split(" ").collect();
	split.into_iter().map(|x| {
		if x == "??" {
			None
		} else {
			Some(u8::from_str_radix(x, 16).unwrap())
		}
	}).collect()
}

// Helper function for parsing sigs from CStr pointer

pub unsafe fn parse_sig_cstr(sig_ptr: *const c_char) -> Vec<Option<u8>> {
	let sig_str = CStr::from_ptr(sig_ptr).to_str().unwrap();
	parse_sig_str(sig_str)
}