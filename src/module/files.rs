use crate::internal::headers::{
	get_sig_offset,
	parse_coff_header,
	parse_section_table,
	CoffHeader,
	Section,
	DOS_SIZE, COFF_SIZE, SECTION_SIZE
};

use std::{
	io::{
		Result,
		Seek, Read,
		SeekFrom::{Start, Current},
	},
	fs::File
};

// Individual header parsers

fn read_sig_offset(file: &mut File) -> Result<u32> {
	let mut dos_buffer = [0u8; DOS_SIZE];
	file.read_exact(&mut dos_buffer)?;

	let result = unsafe { get_sig_offset(dos_buffer.as_ptr()) };
	Ok(result)
}

fn read_coff_header(file: &mut File) -> Result<CoffHeader> {
	let mut coff_buffer = [0u8; COFF_SIZE];
	file.read_exact(&mut coff_buffer)?;

	let result = unsafe { parse_coff_header(coff_buffer.as_ptr()) };
	Ok(result)
}

fn read_section_table(file: &mut File, length: u16) -> Result<Vec<Section>> {
	let mut buffer = vec![0u8; length as usize * SECTION_SIZE];
	file.read_exact(&mut buffer)?;

	let result = unsafe { parse_section_table(buffer.as_ptr(), length) };
	Ok(result)
}

// Section metadata

pub fn get_sections_from(file: &mut File) -> Result<Vec<Section>> {
	let cursor = file.stream_position()?;
	file.seek(Start(0))?;

	let sig_offset = read_sig_offset(file)?;
	file.seek(Start(sig_offset as u64))?;

	let pe_header = read_coff_header(file)?;
	file.seek(Current(pe_header.optional_size as i64))?; // Skip optional header

	let result = read_section_table(file, pe_header.section_ct);
	file.seek(Start(cursor)).ok();
	result
}

pub fn lookup_file_section(file: &mut File, name: &str) -> Option<Section> {
	get_sections_from(file)
		.ok()?
		.into_iter()
		.find(|section| section.name == name)
}

// Section reading

pub fn read_section(file: &mut File, section: &Section) -> Result<Vec<u8>> {
	let mut buffer = vec![0u8; section.size];
	file.seek(Start(section.base as u64))?;
	file.read_exact(&mut buffer)?;
	Ok(buffer)
}