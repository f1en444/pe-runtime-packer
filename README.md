# PE Runtime Packer

A lightweight **C++ PE (Portable Executable) inspection and runtime packing tool** for Windows.

The project provides a command-line interface for inspecting 64-bit PE images and applying a configurable packing transformation to an input executable.

## Features

* PE image inspection
* Section enumeration
* Import table inspection
* Export table inspection
* PE header information
* Configurable XOR key
* Configurable section names
* Runtime stub section support
* Entry-point redirection
* C++17 filesystem support
* Windows-native PE tooling

## Commands

### `info`

Inspect a PE file:

```text
pe_runtime info FILE
```

Example:

```text
pe_runtime info example.exe
```

Displays information including:

* Machine type
* PE timestamp
* Preferred image base
* Image size
* Entry-point RVA
* PE characteristics
* DLL characteristics
* Sections
* Imports
* Exports

Example output:

```text
machine           : AMD64
timestamp         : 0x12345678
preferred base    : 0x0000000140000000
size of image     : 0x00123000
entry point RVA   : 0x00001000
characteristics   : 0x0022

sections:
  name       vsize     vaddr     rsize     raw       flags
  .text      00012000  00001000  00012200  00000400  ...
  .rdata     00004000  00014000  00004200  00012600  ...
```

### `pack`

Pack an input PE into an output file:

```text
pe_runtime pack IN OUT [--key 0xNN] [--section NAME] [--stub NAME]
```

Example:

```text
pe_runtime pack input.exe output.exe
```

With options:

```text
pe_runtime pack input.exe output.exe --key 0x5A
```

### Options

| Option           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `--key 0xNN`     | Sets the XOR key used by the packer               |
| `--section NAME` | Selects the section used by the packing operation |
| `--stub NAME`    | Sets the runtime stub section name                |

## Packing Output

After a successful packing operation, the tool reports:

```text
packed OK
  key used         : 0x5A
  encrypted region : RVA 0x00001000  size 0x12000
  stub section     : RVA 0x00020000  size 512 B
  entry point      : 0x00001000  ->  0x00020000
  wrote            : output.exe
```

This provides a quick overview of the transformation performed on the PE image.

## Requirements

* Windows
* Visual Studio 2022
* C++17 or later
* Windows SDK

## Building

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/pe-runtime-packer.git
cd pe-runtime-packer
```

Open the Visual Studio solution/project and build the desired configuration.

The resulting executable can then be used from a terminal:

```text
pe_runtime.exe info example.exe
```

## Project Structure

```text
pe-runtime-packer/
├── pe_image.hpp
├── packer.hpp
├── ...
└── main.cpp
```

The project is separated into PE image handling, packing functionality, and the command-line interface.

## Limitations

This project is intended primarily as a **PE-format and systems-programming project**.

The current implementation is intentionally simple and should not be considered a production-grade executable protection system.

Important areas for future development include:

* More comprehensive PE validation
* Better malformed-file handling
* Additional PE architectures
* More robust relocation handling
* Improved section management
* Stronger integrity validation
* More extensive test coverage

## License

See the LICENSE file for the full license text.
