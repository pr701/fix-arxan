#!/usr/bin/env python
#
# Arxan binary fixer using unpacked dump
#
# Authors:	pr701
# Version:	1.5.4.1
# License:	MIT
#
# History:
# 1.6		2020-11-14 Add support arxan v3
# 1.5.4		2020-11-13 Add support large files (pelib fail access by rva)
# 1.5.3		2020-11-11 Fix header flags
# 1.5.2		2020-11-11 Check arxan import table
# 1.5.1		2020-11-11 Fix checksum
# 1.5		2020-11-11 Get executable info protected by arxan
# 1.4		2020-11-10 Fix warnings, fix SecurityCookie value.
# 1.3		2020-10-22 Add warning for version with tls callback.
# 1.2		2020-08-31 Support new x64 arxan version.
# 1.1		2020-08-31 Refactored tracing and added '-t' argument.
# 1.0		2020-08-17 First version, support x64 terget.
#
# 1. Disable rebase flag (Dll can move)
# 2. Load target to debugger (skip anti-debug ;) )
# 3. Create dump:
#		#1
#		Set breakpoint on after decrypt call and create dump:
#		1. Get Decrypt call address using script
#		2. Trace to first call instruction (breakpoint after).
#		3. Trace over this call and dump.
#		#2
#		Set breakpoint on GetSystemTimeAsFileTime.
#		Dump.
# 4. Use script with dump

import sys
import os
import argparse
import pefile
import distorm3
import shutil

from os import listdir
from os.path import isfile, isdir, join
from struct import *

def bool_type(v):
	if isinstance(v, bool):
		return v
	if v.lower() in ('yes', 'true', 't', 'y', '1'):
		return True
	elif v.lower() in ('no', 'false', 'f', 'n', '0'):
		return False
	else:
		raise argparse.ArgumentTypeError('boolean value expected.')

def exe_file_type(path):
	if not isfile(path):
		raise argparse.ArgumentTypeError('the file does not exist')
	pe = pefile.PE(path, fast_load=True)
	if pe.DOS_HEADER.e_magic != 0x5A4D:
		raise argparse.ArgumentTypeError('the file not executable')
	if pe.FILE_HEADER.Machine != 0x8664 and pe.FILE_HEADER.Machine != 0x014C:
		raise argparse.ArgumentTypeError('unsupported architecture')
	return path

def read_binary(filename):
	data = b''
	with open(filename, 'rb') as f:
		try:
			data = f.read()
		except Exception as e:
			raise
		finally:
			f.close()
	return data

def write_binary(filename, data):
	with open(filename, 'wb') as f:
		try:
			f.write(data)
		except Exception as e:
			raise
		finally:
			f.close()

def fromNullTerminated(name):
	for i in range(len(name)):
		if name[i] == 0:
			return name[:i]
	return name

def is_pe64(pe):
	if pe.FILE_HEADER.Machine == 0x8664:
		return True
	return False

def get_real_section_size(data):
	size = len(data)
	i = size - 1
	while i != 0:
		if data[i] != 0:
			size = i + 1
			break;
		i -= 1
	return size

def get_pe_checksum_offset(data):
	e_lfanew_offset = 0x3c
	e_lfanew = unpack('<L', data[e_lfanew_offset:e_lfanew_offset+4])[0]
	return e_lfanew + 0x58

def calculate_pe_checksum(checksum_offset, data):

	# https://github.com/BitsOfBinary

	data_len = len(data)
	checksum = 0
	top = 2 ** 32

	for i in range(0, int(data_len / 4)):
		# Don't include the CheckSum of the PE in the calculation
		if i == int(checksum_offset / 4):
			continue

		dword = unpack('<L', data[i * 4 : (i * 4) + 4])[0]
		checksum = (checksum & 0xFFFFFFFF) + dword + (checksum >> 32)

		if checksum > top:
			checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

	checksum = (checksum & 0xFFFF) + (checksum >> 16)
	checksum = checksum + (checksum >> 16)
	checksum = checksum & 0xFFFF

	checksum += data_len

	return checksum

class arxan_info:
	present = False
	version = 0
	ep_crypted = True
	text_crypted = True
	access_entry_rva = 0
	access_flag_rva = 0
	decrypt_entry_rva = 0
	build_import_entry_rva = 0
	build_import_flag_rva = 0

# get arxan ep entry
def is_arxan_entry(base, dasm):
	push_entry = 9
	push_count = 0
	for op in dasm:
		if not op.valid:
			return 0
		# entry check
		if op.mnemonic != 'PUSH':
			return 0
		if push_count == push_entry:
			return dasm[0].address - base
		push_count += 1
	return 0

# trace to modify sections right check
def is_dword_check(base, dasm):
	for op in dasm:
		# selfcheck for crypted
		if op.mnemonic == 'MOV' and len(op.operands) \
			and op.operands[0].type == 'Register' \
			and op.operands[0].index is not None \
			and distorm3.Registers[op.operands[0].index] == 'EAX':
			return op.address + op.size + op.operands[1].disp - base
		if op.mnemonic == 'JMP' or op.mnemonic == 'CALL':
			return 0
	return 0

# is build arxan import table
def is_byte_check(base, dasm):
	for op in dasm:
		# selfcheck for crypted
		if op.mnemonic == 'MOVZX' and len(op.operands) \
			and op.operands[0].type == 'Register' \
			and op.operands[0].index is not None \
			and distorm3.Registers[op.operands[0].index] == 'EAX':
			return op.address + op.size + op.operands[1].disp - base
		if op.mnemonic == 'JMP' or op.mnemonic == 'CALL':
			return 0
	return 0

def trace_arxan(pe, addr, condition, skip_condition_count=0, skip_call_count=0, path_file=''):
	max_jmp = 20
	if args.trace:
		print('-----TRACING-----')
	arch = distorm3.Decode32Bits
	if is_pe64(pe):
		arch = distorm3.Decode64Bits
	base = pe.OPTIONAL_HEADER.ImageBase

	pe_image = pe.get_memory_mapped_image()
	if addr:
		trace_start = addr
		jmp_count = 0
		valid = True
		while valid:
			if args.trace:
				print(' >', hex(trace_start))
			data = pe_image[trace_start:trace_start + 0xff]
			if not len(data):
				if args.trace:
					print('INVALID MEM', hex(trace_start))
				if len(path_file):
					offset = pe.get_offset_from_rva(trace_start)
					if offset < 0:
						valid = False
						break
					data = read_binary(path_file)[offset:offset+0xff]
					if not len(data):
						valid = False
						break
					if args.trace:
						print('RETRY >', hex(trace_start))
				else:
					valid = False
					break
			dasm = distorm3.Decompose(trace_start + base, data, arch)
			rva = condition(base, dasm)
			if rva != 0:
				# condition counter
				if skip_condition_count == 0:
					if args.trace:
						print(' RET', hex(rva))
					return rva
				if skip_condition_count > 0:
					skip_condition_count -= 1
			for op in dasm:
				if args.trace:
					print(op)
				# limiter
				if not op.valid or jmp_count > max_jmp:
					if args.trace:
						if not op.valid:
							print('UNSUPPORTED', op.mnemonic)
						if jmp_count > max_jmp:
							print('REACH LIMIT')
					if op.mnemonic == 'DB 0x66': # distorm unsupported instruction, skip
						trace_start = op.address - base + 10
						break
					valid = False
					break
				# arxan v3
				if op.mnemonic == 'LEA' and op.operands[0].type == 'Register' \
					and distorm3.Registers[op.operands[0].index] == 'RBP':
					jmp_count += 1
					trace_start = op.address + op.size + op.operands[1].disp - base
					break
				# next obfuscated node
				if op.mnemonic == 'JMP' or op.mnemonic == 'CALL':
					# call counter
					if op.mnemonic == 'CALL' and skip_call_count > 0:
						skip_call_count -= 1
						continue
					# next node
					jmp_count += 1
					trace_start = op.operands[0].value - base
					break
	return 0

def get_arxan_info(pe, path_file=''):
	arx = arxan_info()

	last_section = pe.FILE_HEADER.NumberOfSections - 1
	if fromNullTerminated(pe.sections[last_section].Name) != b'.text':
		return arx

	arch = distorm3.Decode32Bits
	if is_pe64(pe):
		arch = distorm3.Decode64Bits

	# disasm entry
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	base = pe.OPTIONAL_HEADER.ImageBase
	entry = pe.get_memory_mapped_image()[ep:ep+0x13]

	vm_entry = 0
	entry_point = distorm3.Decompose(base + ep, entry, arch)

	entry_count = len(entry_point)
	if entry_count < 1:
		return arx

	#one of the default entry
	arx.version = 0
	if entry_count >= 2:
		if entry_point[0].valid and entry_point[0].mnemonic == 'SUB' and \
			entry_point[1].valid or entry_point[1].mnemonic == 'CALL':
			arx.version = 1
		if entry_point[0].valid and entry_point[0].mnemonic == 'JMP' and \
			entry_point[1].valid or entry_point[1].mnemonic == 'INT':
			arx.version = 2

	if arx.version == 0:
		return arx
	arx.present = True

	# decrypted entry?
	if len(entry_point) and entry_point[2].valid:
		if arx.version == 1 \
		and entry_point[2].mnemonic == 'ADD' \
		and entry_point[0].operands[1].value == entry_point[2].operands[1].value: # stack restored
			arx.ep_crypted = False
		if arx.version == 2 \
		and entry_point[2].mnemonic == 'CALL': # call init crt
			arx.ep_crypted = False

	# access rwr protection
	arx.access_entry_rva = trace_arxan(pe, ep, is_arxan_entry,
		path_file = path_file)
	if arx.access_entry_rva == 0:
		return arx

	# flag
	arx.access_flag_rva = trace_arxan(pe, arx.access_entry_rva, is_dword_check,
		path_file = path_file)
	if arx.access_flag_rva == 0:
		return arx

	# decrypt entry
	arx.decrypt_entry_rva = trace_arxan(pe, arx.access_entry_rva, is_arxan_entry,
		skip_condition_count = 1,
		skip_call_count = 1,
		path_file = path_file)
	if arx.decrypt_entry_rva == 0:
		return arx

	# build import
	arx.build_import_entry_rva = trace_arxan(pe, arx.access_entry_rva, is_arxan_entry,
		skip_condition_count = 2,
		skip_call_count = 2,
		path_file = path_file)

	# arxan obfuscation
	if arx.build_import_entry_rva == arx.decrypt_entry_rva:
		arx.build_import_entry_rva = 0

	if arx.build_import_entry_rva != 0:
		arx.text_crypted = False
		arx.build_import_flag_rva = trace_arxan(pe, arx.build_import_entry_rva, is_byte_check,
			path_file = path_file)

	return arx

def process_arx_dump(exefile, dumpfile, outfile):
	print('Parse...')
	exe = pefile.PE(exefile, fast_load=True)
	dump = pefile.PE(dumpfile, fast_load=True)

	if not is_pe64(exe):
		raise ValueError('architecture of source binary is not suported')

	print('Tracing...')
	arx_exe = get_arxan_info(exe,path_file=exefile)
	arx_dump = get_arxan_info(dump,path_file=dumpfile)

	if not arx_exe.present or not arx_dump.present: 
		raise ValueError('source binary not protected by arxan or unknown version')

	print('Target:', exefile)
	print('Arxan version:', arx_exe.version)
	print('Crypted code:', arx_exe.text_crypted)
	print('Access entry:\n RVA: %s\n Offset: %s' % ( \
		hex(arx_exe.access_entry_rva),
		hex(exe.get_offset_from_rva(arx_exe.access_entry_rva))))
	print('Memory access flag:\n RVA: %s\n Offset: %s' % ( \
		hex(arx_exe.access_flag_rva),
		hex(exe.get_offset_from_rva(arx_exe.access_flag_rva))))
	print('Decrypt entry:\n RVA: %s\n Offset: %s' % ( \
		hex(arx_exe.decrypt_entry_rva),
		hex(exe.get_offset_from_rva(arx_exe.decrypt_entry_rva))))
	if arx_dump.build_import_entry_rva != 0:
		print('Build import entry: \n RVA: %s\n Offset: %s' % ( \
			hex(arx_dump.build_import_entry_rva),
			hex(exe.get_offset_from_rva(arx_dump.build_import_entry_rva))))
		print('Build import flag: \n RVA: %s\n Offset: %s' % ( \
			hex(arx_dump.build_import_flag_rva),
			hex(exe.get_offset_from_rva(arx_dump.build_import_flag_rva))))

	if not arx_exe.text_crypted: 
		raise ValueError('source binary entry is not encrypted')

	if arx_dump.text_crypted:
		raise ValueError('dump binary is encrypted, required new dump')

	if arx_exe.access_entry_rva != arx_dump.access_entry_rva or arx_exe.access_flag_rva != arx_dump.access_flag_rva:
		raise ValueError('data vary, abort')

	print('Mapping...')
	exe_image = exe.get_memory_mapped_image()
	dump_image = dump.get_memory_mapped_image()

	# check if dump dumped corrected
	import_flag_byte = unpack('<B', exe_image[arx_exe.build_import_flag_rva:arx_exe.build_import_flag_rva + 1])[0]
	if import_flag_byte == 0:
		raise ValueError('the dump binary was made at the wrong stage')

	print('Processing...')
	out = bytearray(read_binary(exefile))

	section_number = exe.FILE_HEADER.NumberOfSections
	if (section_number != dump.FILE_HEADER.NumberOfSections):
		raise ValueError('the number of sections does not match')

	# move decrypted data (without validation, care)
	for i in range(section_number):
		section = exe.sections[i]
		dump_sec = dump.sections[i]
		# section exist in raw
		if section.PointerToRawData and \
		section.VirtualAddress == dump_sec.VirtualAddress:	# one of the properties of the packer: a large virtual address by default
			decrypted = dump_image[section.VirtualAddress:section.VirtualAddress + dump_sec.SizeOfRawData]
			# pelib bug
			if len(decrypted) < dump_sec.SizeOfRawData:
				offset = dump.get_offset_from_rva(section.VirtualAddress)
				if offset < 0:
					raise ValueError('[error] section ' + str(fromNullTerminated(section.Name)) + ' out of range')
				decrypted = read_binary(dumpfile)[offset:offset + dump_sec.SizeOfRawData]
				if not len(decrypted):
					raise ValueError('[error] section ' + str(fromNullTerminated(section.Name)) + ' out of file')
			section_size = get_real_section_size(decrypted)
			# support version with crypted section
			if section_size > section.SizeOfRawData:
				print('[warning]', 'section', str(fromNullTerminated(section.Name)), 'larger than original, packed?')
			out[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData] = decrypted[:section.SizeOfRawData]

	# fix init check
	check_offset = exe.get_offset_from_rva(arx_exe.access_flag_rva)
	if check_offset:
		out[check_offset:check_offset + 4] = pack('<L', 0xCCCCCCCC) #0xDEC0DED0

	# fix import table
	if arx_dump.build_import_flag_rva != 0:
		check_offset = exe.get_offset_from_rva(arx_dump.build_import_flag_rva)
		out[check_offset:check_offset + 1] = pack('<B', 0xCC)

	# restore iat
	print('Restore IAT...')
	iat_rva = exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].VirtualAddress
	iat_size = exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].Size
	iat_off = exe.get_offset_from_rva(iat_rva)
	iat = exe_image[iat_rva:iat_rva + iat_size]
	if len(iat) < iat_size:
		# pelib bugfix
		iat = read_binary(exefile)[iat_off:iat_off + iat_size]
	out[iat_off:iat_off + iat_size] = iat

	# fix config dir data
	cfg_rva = exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].VirtualAddress
	cfg_size = exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].Size
	if cfg_rva != 0:
		print('Fix config directory...')
		cfg_size = unpack('<L', exe_image[cfg_rva:cfg_rva + 4])[0]
		# restore security cookie
		if cfg_size > 0x40:
			header = '<2L2H3L6QL2H2Q'
			securityCookie = unpack(header, exe_image[cfg_rva:cfg_rva + calcsize(header)])[17]
			securityCookie -= exe.OPTIONAL_HEADER.ImageBase
			securityOff = exe.get_offset_from_rva(securityCookie)
			out[securityOff:securityOff + 4] = exe_image[securityCookie:securityCookie + 4]

	# remove invalid cert if present
	cert_offset = exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
	cert_size = exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
	if cert_offset != 0 and cert_size != 0:
		print('Remove cert...')
		exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
		exe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0
		
		# write header
		out[0:exe.sections[0].PointerToRawData] = exe.write()[0:exe.sections[0].PointerToRawData]
		out = out[:-cert_size]

	# fix checksum
	if args.fix_header:
		print('Fix header flags...')
		# restore dll can move flag
		e_lfanew_offset = 0x3c
		e_lfanew = unpack('<L', out[e_lfanew_offset:e_lfanew_offset+4])[0]
		flag_offset = e_lfanew + 0x5e
		flag = unpack('<H', out[flag_offset:flag_offset + 2])[0]
		flag |= 0x0040
		out[flag_offset:flag_offset + 2] = pack('<H', flag)

		print('Fix checksum...')
		checksum_offset = get_pe_checksum_offset(out)
		checksum = calculate_pe_checksum(checksum_offset, out)
		out[checksum_offset:checksum_offset + 4] = pack('<L', checksum)

	# write
	print('Write...')
	write_binary(outfile, out)
	print('Writed to', outfile)

def process_arx_info(exefile):
	print('Parse...')
	exe = pefile.PE(exefile, fast_load=False)

	if not is_pe64(exe):
		raise ValueError('architecture of source binary is not suported')

	print('Tracing...')
	arx_exe = get_arxan_info(exe,path_file=exefile)
	print('Target:', exefile)
	print('Arxan version:', arx_exe.version)
	print('Crypted code:', arx_exe.text_crypted)
	print('Access entry:\n RVA: %s\n Offset: %s' % ( \
		hex(arx_exe.access_entry_rva),
		hex(exe.get_offset_from_rva(arx_exe.access_entry_rva))))
	print('Memory access flag:\n RVA: %s\n Offset: %s' % ( \
		hex(arx_exe.access_flag_rva),
		hex(exe.get_offset_from_rva(arx_exe.access_flag_rva))))
	print('Decrypt entry:\n RVA: %s\n Offset: %s' % ( \
		hex(arx_exe.decrypt_entry_rva),
		hex(exe.get_offset_from_rva(arx_exe.decrypt_entry_rva))))
	if arx_exe.build_import_entry_rva != 0:
		print('Build import entry: \n RVA: %s\n Offset: %s' % ( \
			hex(arx_exe.build_import_entry_rva),
			hex(exe.get_offset_from_rva(arx_exe.build_import_entry_rva))))
		print('Build import flag: \n RVA: %s\n Offset: %s' % ( \
			hex(arx_exe.build_import_flag_rva),
			hex(exe.get_offset_from_rva(arx_exe.build_import_flag_rva))))

# main

parser = argparse.ArgumentParser(prog='fix-arxan', description='Arxan binary info extractor/fixer')

parser.add_argument('-s','--source', action='store', type=exe_file_type, required=True,
					help='source executable file packed by arxan')
parser.add_argument('-d','--dump', action='store', type=exe_file_type,
					help='dump executable file with decrypted sections')
parser.add_argument('-o','--output', action='store', type=str,
					help='output merged executable file')
parser.add_argument('-t','--trace', action='store', type=bool_type, default=False,
					help='out trace log')
parser.add_argument('-f','--fix-header', action='store', type=bool_type, default=True,
					help='fix executable header checksum and rebase flag')

args = parser.parse_args()

filename, extension = os.path.splitext(args.source)
out = filename + '_unp' + extension

if args.output is not None:
	out = args.output

try:
	if args.dump is not None:
		process_arx_dump(args.source, args.dump, out)
	else:
		process_arx_info(args.source)
except Exception as e:
	print('Error: %s' % e)
else:
	print('Done')