use crate::pointer::{read, read_str};

use std::ffi::{CStr, c_char};

pub struct SectionHeader {
	pub count: u16,
	pub offset: u32
}

pub struct Section {
	pub name: String,
	pub size: u32,
	pub base: u32
}

pub unsafe fn get_section_header(base_addr: *const u8) -> SectionHeader {
	// DOS header
	let pe_offset: u32 = read(base_addr, 0x3C);

	// PE header
	let section_ct: u16 = read(base_addr, 0x06);
	let oh_size: u16 = read(base_addr, (pe_offset + 0x14) as isize);

	// Optional header
	let oh_offset = pe_offset + 0x18;

	// Section table
	SectionHeader {
		count: section_ct,
		offset: oh_offset + oh_size as u32
	}
}

pub unsafe fn get_section_table(base_addr: *const u8) -> Vec<Section> {
	let header = get_section_header(base_addr);
	let mut result = Vec::<Section>::new();
	for i in 0..header.count {
		let offset = (header.offset + i as u32 * 0x28) as isize;
		result.push(Section {
			name: read_str(base_addr, offset + 8),
			size: read(base_addr, offset + 0x10),
			base: read(base_addr, offset + 0x14)
		});
	}
	result
}

pub unsafe fn lookup_section_name(base_addr: *const u8, name: &str) -> Option<Section> {
	let table = get_section_table(base_addr);
	for section in table {
		if section.name == name {
			return Some(section);
		}
	}
	None
}

pub unsafe fn lookup_section_cstr(base_addr: *const u8, name_ptr: *const c_char) -> Option<Section> {
	let name = CStr::from_ptr(name_ptr).to_str().unwrap();
	lookup_section_name(base_addr, name)
}