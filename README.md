# Clovo

**CLI tool for advanced password security analysis and generation.**

Clovo helps you analyze password strength (entropy, patterns, crack time) and generate secure, random credentials or passphrases. It supports batch processing, multiple export formats, and compliance checks (NIST, PCI-DSS).

## Key Features

* **Deep Analysis:** Calculates entropy, crack time, and strength score (0-100).
* **Pattern Detection:** Identifies keyboard patterns (qwerty), repetitions, dictionary words, and "leetspeak".
* **Secure Generation:** Create cryptographically strong passwords or memorable passphrases.
* **Compliance:** Validate against NIST, PCI-DSS, or custom policies.
* **Batch & Export:** Process file lists and export to JSON/CSV.

## Quick Start

### Prerequisites

* C Compiler (gcc/clang)
* CMake 3.15+

### Build & Run

```bash
# Clone and build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run the executable
./build/password_checker "test_password"

```

## Usage Cheatsheet

| Goal | Command |
| --- | --- |
| **Analyze Password** | `./build/password_checker "MySecretPass!"` |
| **Generate Password** | `./build/password_checker --generate 20` |
| **Generate Passphrase** | `./build/password_checker --passphrase 4` |
| **Check Compliance** | `./build/password_checker --policy nist "password123"` |
| **Batch Process** | `./build/password_checker --batch list.txt --json` |
| **Compare Passwords** | `./build/password_checker --compare "pass1" "pass2"` |

## Understanding the Output

Clovo rates passwords on a **0-100 scale**:

| Score | Rating | Meaning |
| --- | --- | --- |
| **0-49** | **WEAK** | Vulnerable. Contains patterns or is too short. |
| **50-69** | **MEDIUM** | Acceptable for low-risk accounts. |
| **70-100** | **STRONG** | High entropy, suitable for sensitive data. |

### Example Output

```text
$ ./build/password_checker "Tr0ub4dor&3"

  Length:       11 characters
  Entropy:      56.9 bits
  Crack time:   2.1 years
  Weaknesses:   Dictionary word detected, Leetspeak detected

  Strength Score: 
  ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 35/100 
  Rating: VERY WEAK

```

## Development

**Run Tests:**

```bash
cd build && ctest --output-on-failure

```

**Debug Build:**

```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

```

## License

MIT License - see [LICENSE](https://www.google.com/search?q=LICENSE) for details.