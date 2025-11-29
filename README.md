# 🔐 Passcheck 

## Build
```bash
cmake -B build && cmake --build build
```

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

## Project Structure
```
password-checker/
├── CMakeLists.txt
├── src/              # source files
├── include/          # header files
└── tests/            # test files
```

## License

MIT
