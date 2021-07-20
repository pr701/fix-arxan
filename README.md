# Arxan binary info extractor and fixer

Arxan binary fixer using unpacked executable dump.

## Intro

Arxan is an portable executable file protector that includes features such as:

- code morphing.
- code integrity checking (checksum).
- executable image (section) encryption.

This tool helps to get some information about the loader and a decrypted working image for comfortable research.

**Note: The tool does not automatically deactivate integrity checks and does not deobfuscate code fragments**.

## Loader

Execution of the protection code begins with the **loader**. The loader contains several mandatory functions, which are executed sequentially:

- Function to set full access rights for sections (to decrypt the image).
- Function to decrypt Image.
- Function to create a copy of the import table.

Each function has an entry and exit pattern:

Entry:

```assembly
; save context
push rax
push rcx
push r11
push r9
push rdi
push r10
push r13
push r12
; ...
movupd xmmword ptr ss:[rsp],xmm1
movupd xmmword ptr ss:[rsp + 10],xmm9
movupd xmmword ptr ss:[rsp + 20],xmm15
movupd xmmword ptr ss:[rsp + 30],xmm10
; obfuscated code (jmps)
```

Exit:

```assembly
; restore context
movupd xmm1,xmmword ptr ss:[rsp]
movupd xmm9,xmmword ptr ss:[rsp + 10]
movupd xmm15,xmmword ptr ss:[rsp + 20]
movupd xmm10,xmmword ptr ss:[rsp + 30]
; ...
pop r8
pop rdx
pop rsi
pop r15
pop rdi
pop r9
pop rcx
pop rax
; obfuscated code (jmps)
```

After completing *their task*, functions set variable (`DWORD`) in memory that set the completion of the function's execution phase.

## Entry Point

Loader function executions start from **Entry Point** for version **1** and from **TLS** for version **2**.

**Note: The "rule" of version may not be valid, you need to manually check the TLS entry. Versioning exists only for the convenience of research.**

OEP (Original Entry Point) will be executed after the completion of all loader functions.

# Requirements

- Python > 3.8

- Python modules:

	- [pefile](https://pypi.org/project/pefile/)

	- [distorm3](https://pypi.org/project/distorm3/)

# Installation

## Install Python modules

```sh
pip install pefile
pip install distorm3
```

# Command line options

Arguments:

| Option            | Default | Description                                    |
| ----------------- | ------- | ---------------------------------------------- |
| `-h/--help`       |         | List of available command options              |
| `-s/--source`     |         | source executable file packed by Arxan         |
| `-d/--dump`       |         | dump executable file with decrypted sections   |
| `-o/--output`     |         | output merged executable file                  |
| `-t/--trace`      | `false` | out trace log                                  |
| `-f/--fix-header` | `true`  | fix executable header checksum and rebase flag |

# Using

1. Disable image dynamic rebase flag (Dll can move\) in PE header.
2. Get information about the address of the decryption function with the `s` option.
3. Load the target into the debugger and break on entering the *decrypt_image* function.
4. Disable all breakpoints and trace over to exit from the function or to the next entry.
5. Create a dump (e.g. with [OllyDumpEx](https://low-priority.appspot.com/ollydumpex/)).
6. Use fixer and dump with the `d` option.
7. Ready to research!

## Sample

Just sample, of course, the addresses are unique for each executable file =)

1. Disable image dynamic rebase and get information with the `s` option:

	```shell
	fix-arxan -s samples/test.exe
	Parsing source PE file...
	
	PE file overview
	Reported values are in "Hex | Dec | Bin" form
	
			  Image base:     140000000
			  Size of Image:  72E8E00 | 120491520
			  CheckSum:       0556B36C [6CB35605]
			  Is Dynamic Base (ASLR): False
			  DLL Characteristics:    8120 | 33056 | 1000000100100000
	
	Tracing...
	Target: samples/test.exe
	Arxan version: 2
	Crypted code: True
	
	`set_access_rwx` function entry @:
			  VA:     140E889C0
			  RVA:    00E889C0
			  RAW:    00E87DC0
	`access_flag` variable @:
			  VA:     1422192D9
			  RVA:    022192D9
			  RAW:    022186D9
	`decrypt_image` function entry @:
			  VA:     1466E49AB
			  RVA:    066E49AB
			  RAW:    0495ADAB
	Done
	```

3. Load the target into the debugger and break on `@066E49AB`.
4. Disable all breakpoints, trace over to decrypt image and create dump.
4. Use source and dump with the `d` option:

	```shell
	fix-arxan -s samples/test_file.exe -d samples/test_dump.exe
	Parsing dump file...
	Tracing...
	Target: samples/test.exe
	Arxan version: 2
	Crypted code: False
	
	`set_access_rwx` function entry @:
			  VA:     140E889C0
			  RVA:    00E889C0
			  RAW:    00E889C0
	`access_flag` variable @:
			  VA:     1422192D9
			  RVA:    022192D9
			  RAW:    022192D9
	`decrypt_image` function entry @:
			  VA:     1466E49AB
			  RVA:    066E49AB
			  RAW:    066E49AB
	`build_import` function entry @:
			  VA:     147077598
			  RVA:    07077598
			  RAW:    07077598
	`build_import` variable @:
			  VA:     147054199
			  RVA:    07054199
			  RAW:    07054199
	
	Mapping...
	Processing...
	Restoring IAT...
	Removing digital signature...
	Writing output...
	Saved to samples/test_unp.exe
	Donese
	```

5. Done.

# Tested protected executable files

These files were successfully tested and decrypted:

- Grand Theft Auto V (**1.0.1737 - 1.0.2060**)
- Red Dead Redemption 2 (**1.0.1207 - 1.0.1311**)
- Age of Empires III: Definitive Edition (**100.12.5208**)
- Call of Duty: Infinite Warfare (**1.0 - 1.2**)
- Call of Duty: Black Ops (**1.0.0.0**)
- Gears 5 (**1.0.0.0**)
