# Arxan binary info extractor and fixer

# Intro

Arxan binary fixer using unpacked executable dump.

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
| `-h/--help`       |         | List of available command options            |
| `-s/--source`     |         | source executable file packed by arxan         |
| `-d/--dump`       |         | dump executable file with decrypted sections   |
| `-o/--output`     |         | output merged executable file                  |
| `-t/--trace`      | `false` | out trace log                                  |
| `-f/--fix-header` | `true`  | fix executable header checksum and rebase flag |

## Using

1. Disable rebase flag (Dll can move)
2. Load target to debugger (skip anti-debug ;) ) and break on TLS.
3. Create dump.
4. Use script with dump.
5. Fix anti-dump if present.
