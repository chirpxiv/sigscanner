use crate::pointer::{read, read_str};

// DOS header

pub const DOS_SIZE: usize = 0x40;

const SIG_OFFSET_OFFSET: isize = 0x3C;

// COFF header

pub const COFF_SIZE: usize = 0x18;

pub struct CoffHeader {
	pub section_ct: u16,
	pub optional_size: u16
}

// PE header

pub struct PeHeader {
	pub coff_offset: u32,
	pub coff: CoffHeader
}

impl PeHeader {
	pub fn get_optional_offset(&self) -> usize {
		self.coff_offset as usize + COFF_SIZE
	}

	pub fn get_sections_offset(&self) -> usize {
		self.get_optional_offset() + self.coff.optional_size as usize
	}

	pub fn get_sections_size(&self) -> usize {
		self.coff.section_ct as usize * SECTION_SIZE
	}
}

// Section table

pub const SECTION_SIZE: usize = 0x28;

pub struct Section {
	pub name: String,
	pub size: usize,
	pub base: usize
}

// Parsing

pub unsafe fn get_sig_offset(base: *const u8) -> u32 {
	read(base, SIG_OFFSET_OFFSET)
}

pub unsafe fn parse_coff_header(addr: *const u8) -> CoffHeader {
	CoffHeader {
		section_ct: read::<u16>(addr, 0x06),
		optional_size: read::<u16>(addr, 0x14)
	}
}

pub unsafe fn parse_section_table(addr: *const u8, length: u16) -> Vec<Section> {
	let mut result = Vec::new();
	for i in 0..length {
		let offset = (i as usize * SECTION_SIZE) as isize;
		result.push(Section {
			name: read_str(addr, offset),
			size: read::<u32>(addr, offset + 0x10) as usize,
			base: read::<u32>(addr, offset + 0x14) as usize
		});
	}
	result
}

// PE header

pub unsafe fn parse_pe_header(base: *const u8) -> PeHeader {
	let coff_offset = get_sig_offset(base);
	let coff_header = parse_coff_header(base.add(coff_offset as usize));
	PeHeader {
		coff_offset,
		coff: coff_header
	}
}