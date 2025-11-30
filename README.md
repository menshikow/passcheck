# 🔐 Passcheck

> **CLI tool to analyze password strength and generate secure passwords**

[![C17](https://img.shields.io/badge/C-17-blue.svg?style=flat-square)](https://en.wikipedia.org/wiki/C17_(C_standard_revision))
[![CMake](https://img.shields.io/badge/CMake-3.15+-064F8C.svg?style=flat-square&logo=cmake)](https://cmake.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg?style=flat-square)]()

> • [Installation](#build) • [Usage](#usage) • [Examples](#example)

## Build

#### Normal build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

#### Debug build (for debugging with gdb/LLDB)

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

Debug builds include symbols, so you can step through code, inspect variables, and watch memory.

Release builds are optimized and don’t include debug info.

## Usage

```bash
# Check a password
./build/password_checker "mypassword123"

# Generate a password
./build/password_checker --generate 16
```

## What It Checks

- Length (at least 8 characters recommended)
- Lowercase letters
- Uppercase letters  
- Numbers
- Symbols

Scores passwords from 0-100 and rates them as:

- **VERY WEAK** (0-39)
- **WEAK** (40-59)
- **MODERATE** (60-79)
- **STRONG** (80-100)

## Example

```bash
$ ./build/password_checker "hello"

=== PASSWORD ANALYSIS ===
Length: 5 characters
Contains lowercase: ✓
Contains uppercase: ✗
Contains digits: ✗
Contains symbols: ✗

Strength Score: 15/100
Rating: VERY WEAK
```

## Running Tests

```bash
./build/test_analyzer
./build/test_generator
```

## Requirements

- C compiler (gcc or clang)
- CMake 3.15+
