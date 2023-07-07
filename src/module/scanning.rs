// Dependencies

pub use crate::headers::{Section, PeHeader};

use crate::{
	signatures::parse_sig_cstr,
	headers::{
		parse_pe_header,
		parse_section_table
	}
};

use std::{
	ptr,
	ffi::{CStr, c_char}
};

// Scan memory for sig vec

pub unsafe fn find_sig(start_addr: *const u8, size: usize, sig: Vec<Option<u8>>) -> *const u8 {
	// not ideal but this is an optimisation overall because accessing vectors is slow
	let sig_bytes = sig.as_slice();
	let sig_len = sig_bytes.len();

	let mut sig_index = 0;
	for i in 0 .. size {
		let ptr = start_addr.add(i);

		let sig_byte = sig_bytes[sig_index];
		let matches = match sig_byte {
			Some(s) => s == *ptr,
			None => true
		};

		if matches {
			sig_index += 1;
			if sig_index != sig_len { continue; }

			let start = ptr.sub(sig_index - 1);
			return if *start == 0xE8 { // relative call
				let asm_ptr = *(start.add(1) as *const u32);
				start.sub(!asm_ptr as usize).add(4)
			} else {
				start
			}
		} else if sig_index > 0 {
			sig_index = 0;
		}
	}
	
	ptr::null()
}

pub unsafe fn find_sig_cstr(start_addr: *const u8, size: usize, sig_ptr: *const c_char) -> *const u8 {
	let sig = parse_sig_cstr(sig_ptr);
	find_sig(start_addr, size, sig)
}

// Section lookup

pub unsafe fn get_pe_header(base_addr: *const u8) -> PeHeader {
	parse_pe_header(base_addr)
}

pub unsafe fn get_module_sections(base_addr: *const u8) -> Vec<Section> {
	let header = get_pe_header(base_addr);

	let addr = base_addr.add(header.get_sections_offset());
	parse_section_table(addr, header.coff.section_ct)
}

pub unsafe fn lookup_section_name(base_addr: *const u8, name: &str) -> Option<Section> {
	get_module_sections(base_addr)
		.into_iter()
		.find(|section| section.name == name)
}

pub unsafe fn lookup_section_cstr(base_addr: *const u8, name: *const c_char) -> Option<Section> {
	let name = CStr::from_ptr(name).to_str().ok()?;
	lookup_section_name(base_addr, name)
}