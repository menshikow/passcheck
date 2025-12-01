# 🔐 Passcheck

> **CLI tool to analyze password strength and generate secure passwords**

[![C17](https://img.shields.io/badge/C-17-blue.svg?style=flat-square)](https://en.wikipedia.org/wiki/C17_(C_standard_revision))
[![CMake](https://img.shields.io/badge/CMake-3.15+-064F8C.svg?style=flat-square&logo=cmake)](https://cmake.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg?style=flat-square)](https://youtu.be/dQw4w9WgXcQ?si=Xy0-u8pds4z-7CPV)

> • [Installation](#installation) • [Usage](#usage) • [Testing](#testing) • [Examples](#examples)

## Installation

### Requirements

- C compiler (gcc or clang)
- CMake 3.15+

### Build from Source

#### Release Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

#### Debug Build

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

**Note:** Debug builds include symbols for debugging with gdb/LLDB. Release builds are optimized and don't include debug info.

## Usage

### Analyze a Password

```bash
./build/password_checker "mypassword123"
```

### Generate a Secure Password

```bash
# Generate 16-character password
./build/password_checker --generate 16

# Generate 24-character password
./build/password_checker --generate 24
```

### Strength Levels

Passwords are scored from 0-100 and rated as:

| Score    | Rating        | Description                              |
|----------|---------------|------------------------------------------|
| 0-29     | VERY WEAK     | Easily crackable, change immediately     |
| 30-49    | WEAK          | Vulnerable to attacks                    |
| 50-69    | MEDIUM        | Acceptable for low-security accounts     |
| 70-84    | STRONG        | Good for most purposes                   |
| 85-100   | VERY STRONG   | Excellent, highly secure                 |

## Examples

### Weak Password

```bash
$ ./build/password_checker "hello"

=== PASSWORD ANALYSIS ===
Length: 5 characters
Contains lowercase: ✓
Contains uppercase: ✗
Contains digits: ✗
Contains symbols: ✗
Entropy: 23.5 bits
Strength Score: 15/100
Rating: VERY WEAK

⚠️  Recommendations:
  - Use at least 8 characters
  - Add uppercase letters
  - Add numbers
  - Add symbols
```

### Strong Password

```bash
$ ./build/password_checker "MyS3cur3P@ssw0rd!"

=== PASSWORD ANALYSIS ===
Length: 16 characters
Contains lowercase: ✓
Contains uppercase: ✓
Contains digits: ✓
Contains symbols: ✓
Entropy: 95.2 bits
Strength Score: 95/100
Rating: VERY STRONG

✓ Excellent password!
```

### Generate Password

```bash
$ ./build/password_checker --generate 16

Generated Password: K7$mP2@nX9#qL4vR
Strength Score: 92/100
Rating: VERY STRONG
```

## Testing

The project includes unit tests using the [Unity](https://github.com/ThrowTheSwitch/Unity) testing framework.

### Run All Tests

```bash
# Option 1: Using CTest
cd build
ctest --output-on-failure

# Option 2: Using make target
make run_tests

# Option 3: Run individually
./build/test_analyzer
./build/test_generator
```

### Run Specific Tests

```bash
# Analyzer tests only
cd build
make run_analyzer_tests

# Generator tests only
make run_generator_tests
```

### Test Output Example

```bash
$ ./build/test_analyzer

test_analyzer.c:15:test_null_password:PASS
test_analyzer.c:23:test_empty_password:PASS
test_analyzer.c:30:test_lowercase_only:PASS
test_analyzer.c:38:test_uppercase_only:PASS
test_analyzer.c:46:test_mixed_characters:PASS
...
-----------------------
35 Tests 0 Failures 0 Ignored 
OK
```

## Development

### Build with Debug Symbols

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

# Debug with gdb
gdb ./build-debug/password_checker
```

### Clean Build

```bash
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Dependencies

- **Unity** (testing framework) - Automatically fetched during build via CMake FetchContent
- **math.h** (standard C library) - For entropy calculations

No manual dependency installation required

## License

MIT License [LICENSE](LICENSE)

## Acknowledgments

- [Unity Test Framework](https://github.com/ThrowTheSwitch/Unity) - source for the C testing framework, which is used
- Password strength algorithms based on NIST guidelines (National Institute of Standards and Technology for cybersecurity, risk management, and privacy.)
