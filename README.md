# Clovo 

CLI tool for analyzing password strength and generating new. Clovo provides advanced password security analysis including pattern detection, repetition analysis, dictionary word checking, crack time estimation, policy validation, and batch processing.

[![C17](https://img.shields.io/badge/C-17-blue.svg?style=flat-square)](https://en.wikipedia.org/wiki/C17_(C_standard_revision))
[![CMake](https://img.shields.io/badge/CMake-3.15+-064F8C.svg?style=flat-square&logo=cmake)](https://cmake.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg?style=flat-square)](https://github.com)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Password Analysis](#password-analysis)
- [Examples](#examples)
- [Testing](#testing)
- [Development](#development)
- [License](#license)

## Features

### Password Analysis
- **Character Analysis**: Detects lowercase, uppercase, digits, and symbols
- **Entropy Calculation**: Measures password randomness and unpredictability
- **Pattern Detection**: Identifies sequential patterns (123, abc) and keyboard patterns (qwerty, asdf)
- **Repetition Detection**: Finds repeated characters and repeated patterns
- **Dictionary Word Detection**: Checks for common dictionary words
- **Leetspeak Detection**: Detects common character substitutions (P@ssw0rd → password)
- **Crack Time Estimation**: Estimates time to crack based on entropy
- **Strength Scoring**: 0-100 point scoring system with pattern penalties

### Password Generation
- **Secure Random Generation**: Uses system random number generators
- **Customizable Length**: Generate passwords of any length (8-256 characters)
- **Passphrase Generation**: Generate memorable passphrases with multiple words
- **Common Password Filtering**: Automatically avoids generating common passwords
- **Character Set Control**: Includes lowercase, uppercase, digits, and symbols

### Advanced Features
- **Batch Processing**: Analyze multiple passwords from a file
- **Multiple Output Formats**: Text, JSON, and CSV output formats
- **Policy Validation**: Check passwords against NIST, PCI-DSS, and custom policies
- **Password Comparison**: Compare two passwords for similarity
- **Export Functionality**: Export analysis results to files

## Installation

### Requirements

- C compiler (gcc or clang)
- CMake 3.15 or higher
- Make (usually included with build tools)

### Build from Source

#### Release Build (Recommended)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The executable will be located at `build/password_checker`.

#### Debug Build

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

Debug builds include symbols for debugging with gdb/LLDB. Release builds are optimized for performance.

## Usage

### Analyze a Password

```bash
./build/password_checker "your_password_here"
```

### Generate a Secure Password

```bash
# Generate 16-character password (default)
./build/password_checker --generate

# Generate custom length password
./build/password_checker --generate 24

# Generate 32-character password
./build/password_checker --generate 32
```

### Generate a Passphrase

```bash
# Generate 4-word passphrase (default)
./build/password_checker --passphrase

# Generate custom word count passphrase
./build/password_checker --passphrase 5
```

### Batch Processing

```bash
# Analyze passwords from a file
./build/password_checker --batch passwords.txt

# Batch processing with JSON output
./build/password_checker --batch passwords.txt --json

# Batch processing with CSV output and save to file
./build/password_checker --batch passwords.txt --csv --output results.csv
```

### Output Formats

```bash
# JSON output
./build/password_checker --json "password123"

# CSV output
./build/password_checker --csv "password123"

# Export to file
./build/password_checker --export json results.json "password123"
./build/password_checker --export csv results.csv "password123"
```

### Policy Validation

```bash
# Validate against NIST policy
./build/password_checker --policy nist "password123"

# Validate against PCI-DSS policy
./build/password_checker --policy pci "password123"

# Validate against basic policy
./build/password_checker --policy basic "password123"
```

### Password Comparison

```bash
# Compare two passwords for similarity
./build/password_checker --compare "old_password" "new_password"
```

### Help

```bash
./build/password_checker --help
```

## Password Analysis

### Strength Levels

Passwords are scored from 0-100 and rated as follows:

| Score    | Rating        | Description                              |
|----------|---------------|------------------------------------------|
| 0-29     | VERY WEAK     | Easily crackable, change immediately     |
| 30-49    | WEAK          | Vulnerable to attacks                    |
| 50-69    | MEDIUM        | Acceptable for low-security accounts     |
| 70-84    | STRONG        | Good for most purposes                   |
| 85-100   | VERY STRONG   | Excellent, highly secure                 |

### Scoring System

The scoring algorithm considers:

- **Length** (0-40 points): Longer passwords score higher
- **Character Variety** (0-40 points): Mix of lowercase, uppercase, digits, and symbols
- **Entropy** (0-20 points): Measures randomness and unpredictability
- **Pattern Penalties** (up to -60 points): Deducts points for:
  - Sequential patterns (123, abc)
  - Keyboard patterns (qwerty, asdf)
  - Repeated characters (aaa, 111)
  - Repeated patterns (abcabc)
  - Dictionary words
  - Leetspeak patterns

### Security Metrics

- **Entropy**: Measured in bits, indicates password randomness
- **Crack Time**: Estimated time to crack assuming 1 billion attempts per second
- **Weaknesses**: Lists detected patterns and vulnerabilities

### Policy Types

- **NIST**: Modern password guidelines (8+ chars, no common patterns)
- **PCI-DSS**: Payment card industry standards (7+ chars, mixed case, digits)
- **BASIC**: Simple requirements (8+ chars, lowercase)

## Examples

### Weak Password with Patterns

```bash
$ ./build/password_checker "password123"

═══════════════════════════════════════════════════════════
  PASSWORD ANALYSIS
═══════════════════════════════════════════════════════════

  Characteristics:
  ──────────────────────────────────────────────────────────
  Length:            11 characters
  Character types:
    Lowercase:     Yes
    Uppercase:     No
    Digits:        Yes
    Symbols:       No

  Security metrics:
  ──────────────────────────────────────────────────────────
  Entropy:          56.9 bits
  Crack time:       2.1 years

  Weaknesses detected:
  ──────────────────────────────────────────────────────────
    - Sequential pattern found (e.g., 123, abc)
    - Dictionary word detected
    - Pattern penalty: -40 points

  Strength Score:
  ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 15/100

  Rating:          VERY WEAK
```

### Strong Password

```bash
$ ./build/password_checker "MyS3cur3P@ssw0rd!"

═══════════════════════════════════════════════════════════
  PASSWORD ANALYSIS
═══════════════════════════════════════════════════════════

  Characteristics:
  ──────────────────────────────────────────────────────────
  Length:            17 characters
  Character types:
    Lowercase:     Yes
    Uppercase:     Yes
    Digits:        Yes
    Symbols:       Yes

  Security metrics:
  ──────────────────────────────────────────────────────────
  Entropy:          111.4 bits
  Crack time:       5.54e+16 years

  Strength Score:
  ████████████████████████████████████████ 100/100

  Rating:          VERY STRONG

  Excellent password! This password is highly secure.
```

### Generate Password

```bash
$ ./build/password_checker --generate 16

═══════════════════════════════════════════════════════════
  GENERATED PASSWORD
═══════════════════════════════════════════════════════════

  Password:
  >5X05*xJ.j21ej+Q
  Length:           16 characters

  Strength Score:
  ████████████████████████████████████████ 100/100

  Rating:          VERY STRONG

  Password generated successfully!
```

### Generate Passphrase

```bash
$ ./build/password_checker --passphrase 4

═══════════════════════════════════════════════════════════
  GENERATED PASSWORD
═══════════════════════════════════════════════════════════

  Password:
  lighthouse-waterfall-apple-banana
  Length:           33 characters

  Strength Score:
  ██████████████████████████░░░░░░░░░░░░░░ 65/100

  Rating:          MEDIUM

  Password generated successfully!
```

### JSON Output

```bash
$ ./build/password_checker --json "password123"

{
  "password": "password123",
  "length": 11,
  "entropy": 56.87,
  "crack_time_seconds": 65810851.92,
  "crack_time": "2.1 years",
  "score": 0,
  "rating": "VERY WEAK",
  "has_lowercase": true,
  "has_uppercase": false,
  "has_digits": true,
  "has_symbols": false,
  "has_sequential_pattern": true,
  "has_keyboard_pattern": false,
  "has_repeated_chars": false,
  "has_repeated_pattern": false,
  "contains_dictionary_word": true,
  "pattern_penalty": 55
}
```

### Password Comparison

```bash
$ ./build/password_checker --compare "password" "password1"

Password Comparison:
──────────────────────────────────────────────────────────
Similarity Score: 88.89%
Edit Distance: 1
Common Characters: 8
Common Positions: 8
Too Similar: Yes

Warning: These passwords are too similar!
```

### Policy Validation

```bash
$ ./build/password_checker --policy nist "password123"

Policy Validation (NIST):
──────────────────────────────────────────────────────────
Status: FAILED

Violations:
  - Contains sequential patterns
  - Contains common dictionary word
```

### Batch Processing

```bash
$ cat passwords.txt
password
qwerty
MyS3cur3P@ssw0rd!

$ ./build/password_checker --batch passwords.txt --csv --output results.csv
Exported 3 results to results.csv
```

## Testing

The project includes comprehensive unit tests using the [Unity](https://github.com/ThrowTheSwitch/Unity) testing framework.

### Run All Tests

```bash
# Option 1: Using CTest (recommended)
cd build
ctest --output-on-failure

# Option 2: Using make target
make run_tests

# Option 3: Run individually
./build/test_analyzer
./build/test_generator
```

### Run Specific Test Suites

```bash
# Analyzer tests only
cd build
make run_analyzer_tests

# Generator tests only
make run_generator_tests
```

### Test Coverage

The test suite includes:
- Null and empty password handling
- Character type detection
- Length analysis
- Entropy calculations
- Strength level determination
- Pattern detection
- Repetition detection
- Dictionary word checking
- Password generation validation

## Development

### Project Structure

```
clovo/
├── include/clovo/     # Header files
│   ├── analyzer.h     # Password analysis functions
│   ├── generator.h    # Password generation functions
│   ├── ui.h           # User interface functions
│   ├── policy.h       # Policy validation functions
│   ├── comparison.h   # Password comparison functions
│   └── export.h       # Export functionality
├── src/                # Source files
│   ├── analyzer.c      # Analysis implementation
│   ├── generator.c     # Generation implementation
│   ├── ui.c            # UI implementation
│   ├── policy.c        # Policy validation
│   ├── comparison.c    # Password comparison
│   ├── export.c        # Export functionality
│   └── main.c          # Main entry point
├── tests/              # Test files
│   ├── test_analyzer.c
│   └── test_generator.c
├── data/               # Data files
│   └── common_passwords.txt
└── CMakeLists.txt      # Build configuration
```

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

### Code Style

- C17 standard
- Lowercase comments with casual style
- Consistent indentation
- Clear function and variable names

## Dependencies

- **Unity Test Framework**: Automatically fetched during build via CMake FetchContent
- **Standard C Library**: math.h for entropy calculations

No manual dependency installation required. All dependencies are handled automatically by CMake.

## Contributing

Contributions are welcome! Please ensure that:

1. All tests pass (`ctest --output-on-failure`)
2. Code follows the existing style
3. New features include appropriate tests

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Unity Test Framework](https://github.com/ThrowTheSwitch/Unity) - C testing framework
- Password strength algorithms based on NIST guidelines
- Common passwords list compiled from various security research sources

## Security Note

This tool is designed for password strength analysis and generation. Always use strong, unique passwords for important accounts. Consider using a password manager for secure password storage and generation.
