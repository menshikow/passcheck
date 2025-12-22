#ifndef POLICY_H
#define POLICY_H

#include <stdbool.h>

// policy types
typedef enum {
  POLICY_CUSTOM,
  POLICY_NIST,
  POLICY_PCI_DSS,
  POLICY_BASIC
} policy_type_t;

// policy requirements
typedef struct {
  int min_length;
  int max_length;
  bool require_lowercase;
  bool require_uppercase;
  bool require_digits;
  bool require_symbols;
  bool allow_common_passwords;
  bool allow_sequential_patterns;
  bool allow_repeated_chars;
  int min_entropy;
} password_policy_t;

// policy validation result
typedef struct {
  bool passed;
  int violations_count;
  char violations[10][128]; // max 10 violation messages
} policy_result_t;

// initialize policy with defaults
void init_policy(password_policy_t *policy, policy_type_t type);

// validate password against policy
policy_result_t validate_policy(const char *password,
                                const password_policy_t *policy);

// get policy name
const char *policy_type_to_string(policy_type_t type);

#endif
