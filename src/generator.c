#include "slovo/generator.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// system-oriented functions
#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <sys/random.h>
#include <unistd.h>
#endif

// character sets
static const char LOWERCASE[] = "abcdefghijklmnopqrstuvwxyz";
static const char UPPERCASE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char SYMBOLS[] = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
static const char DIGITS[] = "0123456789";

// common passwords loaded from file
static char **common_passwords_list = NULL;
static size_t common_passwords_count = 0;

// random byte generation function
static int get_random_bytes(unsigned char *buffer, size_t size) {
#ifdef _WIN32
  NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)size,
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  return (status == 0) ? 0 : -1;

#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
  ssize_t result = 0;
  size_t bytes_read = 0;

  // read until all bytes are gathered
  while (bytes_read < size) {
    result = getrandom(buffer + bytes_read, size - bytes_read, 0);

    if (result == -1) {
      if (errno == EINTR) {
        // interrupted by signal, retry
        continue;
      }
      // error in getrandom (e.g., EFAULT, ENOSYS, etc.)
      break;
    } else if (result == 0) {
      // getrandom returned 0 (shouldn't happen without GRND_NONBLOCK)
      break;
    }
    bytes_read += (size_t)result;
  }

  // fallback to /dev/urandom if not all bytes were read
  if (bytes_read < size) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp)
      return -1;
    size_t n = fread(buffer + bytes_read, 1, size - bytes_read, fp);
    fclose(fp);
    bytes_read += n;
  }

  return (bytes_read == size) ? 0 : -1;
#else
  // fallback for other systems using /dev/urandom
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp)
    return -1;
  size_t n = fread(buffer, 1, size, fp);
  fclose(fp);
  return (n == size) ? 0 : -1;
#endif
}

//

generator_error_t load_common_passwords(const char *filepath) {
  FILE *file = fopen(filepath, "r");
  if (!file) {
    // strerror(errno) for error reporting
    fprintf(stderr, "Failed to open common passwords file: %s (%s)\n", filepath,
            strerror(errno));
    return GEN_ERROR_FILE_ACCESS;
  }

  // count lines for allocation
  char line[256];
  size_t count = 0;
  while (fgets(line, sizeof(line), file)) {
    count++;
  }

  if (count == 0) {
    fclose(file);
    fprintf(stderr, "File is empty or failed to read: %s\n", filepath);
    return GEN_ERROR_FILE_ACCESS;
  }

  // allocate memory for passwords list
  common_passwords_list = malloc(count * sizeof(char *));
  if (!common_passwords_list) {
    fclose(file);
    fprintf(stderr, "Memory allocation failed for common passwords.\n");
    return GEN_ERROR_NULL_POINTER;
  }

  rewind(file);
  size_t index = 0;
  while (fgets(line, sizeof(line), file) && index < count) {
    // remove newline
    line[strcspn(line, "\r\n")] = 0;
    if (strlen(line) > 0) {
      // allocate only if strdup succeeds
      char *dup = strdup(line);
      if (dup) {
        common_passwords_list[index] = dup;
        index++;
      } else {
        // handle strdup failure (low memory)
        free_common_passwords();
        fprintf(stderr, "Memory allocation failed for password entry.\n");
        fclose(file);
        return GEN_ERROR_NULL_POINTER;
      }
    }
  }
  common_passwords_count = index;

  fclose(file);
  printf("Loaded %zu common passwords\n", common_passwords_count);
  return GEN_SUCCESS; // Return defined success enum
}

void free_common_passwords(void) {
  if (common_passwords_list) {
    for (size_t i = 0; i < common_passwords_count; i++) {
      free(common_passwords_list[i]);
    }
    free(common_passwords_list);
    common_passwords_list = NULL;
    common_passwords_count = 0;
  }
}

// initialize default options
void init_generator_options(generator_options_t *opts) {
  if (!opts)
    return;

  // NIST-compliant defaults
  opts->min_length = 8;  // NIST minimum
  opts->max_length = 64; // NIST recommended max
  opts->include_lowercase = true;
  opts->include_uppercase = true;
  opts->include_digits = true;
  opts->include_symbols = true;
  opts->check_common = true;
}

generator_error_t init_generator(const char *data_dir) {
  if (!data_dir)
    return GEN_ERROR_NULL_POINTER;

  char filepath[512];
  snprintf(filepath, sizeof(filepath), "%s/common_passwords.txt", data_dir);

  // check for success/failure based on the return type
  if (load_common_passwords(filepath) != GEN_SUCCESS) {
    fprintf(stderr,
            "Warning: Failed to load external common passwords list.\n");
    // continue execution relying on the minimal built-in list
  }

  return GEN_SUCCESS;
}

void cleanup_generator(void) { free_common_passwords(); }

// generation logic
generator_error_t generate_password(char *buffer, size_t buffer_size,
                                    size_t length,
                                    const generator_options_t *opts) {

  if (!buffer)
    return GEN_ERROR_NULL_POINTER;
  if (buffer_size < length + 1)
    return GEN_ERROR_BUFFER_TOO_SMALL;

  // use default if option not provided
  generator_options_t default_opts;
  if (!opts) {
    init_generator_options(&default_opts);
    opts = &default_opts;
  }

  // validate length
  if (length < opts->min_length || length > opts->max_length) {
    return GEN_ERROR_INVALID_LENGTH;
  }

  // sanity check if the user is ahuel v krai
  if (length > 256) {
    return GEN_ERROR_INVALID_LENGTH;
  }

  // build character set
  char charset[256] = "";
  if (opts->include_lowercase) {
    strcat(charset, LOWERCASE);
  }
  if (opts->include_uppercase) {
    strcat(charset, UPPERCASE);
  }
  if (opts->include_digits) {
    strcat(charset, DIGITS);
  }
  if (opts->include_symbols) {
    strcat(charset, SYMBOLS);
  }

  if (charset[0] == '\0') {
    return GEN_ERROR_NO_CHARSET;
  }

  generator_error_t status = GEN_SUCCESS;
  size_t max_attempts = 5; // safety cap for common password checks
  size_t attempts = 0;

  do {
    if (attempts >= max_attempts) {
      return GEN_ERROR_COMMON_PASSWORD;
    }
    attempts++;

    unsigned char *random_bytes = malloc(length);
    if (!random_bytes) {
      return GEN_ERROR_NULL_POINTER;
    }

    size_t charset_len = strlen(charset);
    size_t max_acceptable = 256 - (256 % charset_len);

    for (size_t i = 0; i < length; i++) {
      unsigned char random_val;

      do {
        if (get_random_bytes(&random_val, 1) != 0) {
          free(random_bytes);
          return GEN_ERROR_RANDOM_FAILED;
        }
      } while (random_val >= max_acceptable);

      buffer[i] = charset[random_val % charset_len];
    }
    buffer[length] = '\0';
    free(random_bytes);

    if (opts->check_common && is_common_password(buffer)) {
      status = GEN_ERROR_COMMON_PASSWORD;
      continue;
    } else {
      status = GEN_SUCCESS;
      break;
    }

  } while (status != GEN_SUCCESS);

  return status;
}

// check if password is common
bool is_common_password(const char *ps) {
  if (!ps)
    return false;

  char lower_ps[256];
  size_t len = strlen(ps);

  if (len >= sizeof(lower_ps)) {
    len = sizeof(lower_ps) - 1;
  }

  // convert to lowercase
  for (size_t i = 0; i < len; i++) {
    lower_ps[i] = (char)tolower((unsigned char)ps[i]);
  }
  lower_ps[len] = '\0';

  // check against loaded common passwords
  for (size_t i = 0; i < common_passwords_count; i++) {
    if (strcmp(lower_ps, common_passwords_list[i]) == 0) {
      return true;
    }
  }

  // fallback minimal list
  const char *minimal_common[] = {
      "111111",     "123123",    "12345", "123456",   "12345678", "123456789",
      "1234567890", "abc123",    "admin", "football", "letmein",  "monkey",
      "password",   "password1", "qwert", "qwerty",   "welcome",  NULL,
  };

  for (int i = 0; minimal_common[i] != NULL; i++) {
    if (strcmp(lower_ps, minimal_common[i]) == 0) {
      return true;
    }
  }

  return false;
}

// helper function to get error message string
const char *generator_error_string(generator_error_t error) {
  switch (error) {
  case GEN_SUCCESS:
    return "Success";
  case GEN_ERROR_INVALID_LENGTH:
    return "Invalid password length";
  case GEN_ERROR_NO_CHARSET:
    return "No character sets selected";
  case GEN_ERROR_BUFFER_TOO_SMALL:
    return "Output buffer too small";
  case GEN_ERROR_RANDOM_FAILED:
    return "Failed to generate random data";
  case GEN_ERROR_COMMON_PASSWORD:
    return "Generated password is too common (max retries exceeded)";
  case GEN_ERROR_NULL_POINTER:
    return "NULL pointer provided or memory allocation failed";
  case GEN_ERROR_FILE_ACCESS:
    return "Failed to read common password file";
  default:
    return "Unknown error";
  }
}