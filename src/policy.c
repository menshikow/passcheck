#include "clovo/policy.h"
#include "clovo/analyzer.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

void init_policy(password_policy_t *policy, policy_type_t type) {
  if (!policy)
    return;

  switch (type) {
  case POLICY_NIST:
    policy->min_length = 8;
    policy->max_length = 128;
    policy->require_lowercase = false;
    policy->require_uppercase = false;
    policy->require_digits = false;
    policy->require_symbols = false;
    policy->allow_common_passwords = false;
    policy->allow_sequential_patterns = false;
    policy->allow_repeated_chars = false;
    policy->min_entropy = 0;
    break;

  case POLICY_PCI_DSS:
    policy->min_length = 7;
    policy->max_length = 0;
    policy->require_lowercase = true;
    policy->require_uppercase = true;
    policy->require_digits = true;
    policy->require_symbols = false;
    policy->allow_common_passwords = false;
    policy->allow_sequential_patterns = false;
    policy->allow_repeated_chars = false;
    policy->min_entropy = 0;
    break;

  case POLICY_BASIC:
    policy->min_length = 8;
    policy->max_length = 0;
    policy->require_lowercase = true;
    policy->require_uppercase = false;
    policy->require_digits = false;
    policy->require_symbols = false;
    policy->allow_common_passwords = true;
    policy->allow_sequential_patterns = true;
    policy->allow_repeated_chars = true;
    policy->min_entropy = 0;
    break;

  case POLICY_CUSTOM:
  default:
    policy->min_length = 8;
    policy->max_length = 0;
    policy->require_lowercase = false;
    policy->require_uppercase = false;
    policy->require_digits = false;
    policy->require_symbols = false;
    policy->allow_common_passwords = true;
    policy->allow_sequential_patterns = true;
    policy->allow_repeated_chars = true;
    policy->min_entropy = 0;
    break;
  }
}

policy_result_t validate_policy(const char *password,
                                const password_policy_t *policy) {
  policy_result_t result = {0};

  if (!password || !policy) {
    result.passed = false;
    strcpy(result.violations[result.violations_count++], "Invalid input");
    return result;
  }

  int len = strlen(password);
  password_strength_t analysis = analyze_password(password);

  // check length
  if (policy->min_length > 0 && len < policy->min_length) {
    snprintf(result.violations[result.violations_count++], 128,
             "Password too short (minimum %d characters)", policy->min_length);
  }
  if (policy->max_length > 0 && len > policy->max_length) {
    snprintf(result.violations[result.violations_count++], 128,
             "Password too long (maximum %d characters)", policy->max_length);
  }

  // check character requirements
  if (policy->require_lowercase && !analysis.has_lower) {
    strcpy(result.violations[result.violations_count++],
           "Missing lowercase letters");
  }
  if (policy->require_uppercase && !analysis.has_upper) {
    strcpy(result.violations[result.violations_count++],
           "Missing uppercase letters");
  }
  if (policy->require_digits && !analysis.has_digit) {
    strcpy(result.violations[result.violations_count++], "Missing digits");
  }
  if (policy->require_symbols && !analysis.has_symbol) {
    strcpy(result.violations[result.violations_count++], "Missing symbols");
  }

  // check patterns
  if (!policy->allow_sequential_patterns && analysis.has_sequential_pattern) {
    strcpy(result.violations[result.violations_count++],
           "Contains sequential patterns");
  }
  if (!policy->allow_repeated_chars && analysis.has_repeated_chars) {
    strcpy(result.violations[result.violations_count++],
           "Contains repeated characters");
  }
  if (!policy->allow_common_passwords && analysis.contains_dictionary_word) {
    strcpy(result.violations[result.violations_count++],
           "Contains common dictionary word");
  }

  // check entropy
  if (policy->min_entropy > 0 && analysis.entropy < policy->min_entropy) {
    snprintf(result.violations[result.violations_count++], 128,
             "Entropy too low (minimum %.1f bits)",
             (double)policy->min_entropy);
  }

  result.passed = (result.violations_count == 0);
  return result;
}

const char *policy_type_to_string(policy_type_t type) {
  switch (type) {
  case POLICY_NIST:
    return "NIST";
  case POLICY_PCI_DSS:
    return "PCI-DSS";
  case POLICY_BASIC:
    return "BASIC";
  case POLICY_CUSTOM:
    return "CUSTOM";
  default:
    return "UNKNOWN";
  }
}
