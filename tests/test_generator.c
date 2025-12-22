#include "clovo/generator.h"

#include <stdio.h>
#include <string.h>

static void test(const char *name, int ok) {
  printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
}

int main(void) {
  generator_options_t opts;
  init_generator_options(&opts);

  generator_error_t e = init_generator("./data");
  test("init_generator() returns success even if file missing",
       e == GEN_SUCCESS);

  char buf[64];
  e = generate_password(buf, sizeof(buf), 3, &opts);
  test("length < min_length => GEN_ERROR_INVALID_LENGTH",
       e == GEN_ERROR_INVALID_LENGTH);

  e = generate_password(buf, sizeof(buf), 999, &opts);
  test("length > max_length => GEN_ERROR_INVALID_LENGTH",
       e == GEN_ERROR_INVALID_LENGTH);

  generator_options_t o2 = opts;
  o2.include_lowercase = o2.include_uppercase = o2.include_digits =
      o2.include_symbols = false;
  e = generate_password(buf, sizeof(buf), 10, &o2);
  test("no character sets => GEN_ERROR_NO_CHARSET", e == GEN_ERROR_NO_CHARSET);

  char tiny[5];
  e = generate_password(tiny, sizeof(tiny), 10, &opts);
  test("buffer too small => GEN_ERROR_BUFFER_TOO_SMALL",
       e == GEN_ERROR_BUFFER_TOO_SMALL);

  test("is_common_password(\"password\") == true",
       is_common_password("password") == true);
  test("is_common_password(noncommon) == false",
       is_common_password("N0tInList123!") == false);

  e = generate_password(buf, sizeof(buf), 16, &opts);
  test("generate_password() basic success",
       e == GEN_SUCCESS && strlen(buf) == 16);

  cleanup_generator();
  test("cleanup_generator() completes", 1);

  return 0;
}
