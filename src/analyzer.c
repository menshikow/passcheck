#include "slovo/analyzer.h"

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

password_strength_t analyze_password(const char *ps) {
  password_strength_t result = {0};

  if (ps == NULL) {
    result.level = NO_PASSWORD;
    printf("NO PASSWORD ENTERED\n");
    return result;
  }

  // inter through the string until the end
  for (int i = 0; ps[i] != '\0'; i++) {
    result.length++;
    if (isupper(ps[i])) {
      result.has_upper = 1;
    } else if (isdigit(ps[i])) {
      result.has_digit = 1;
    } else if (islower(ps[i])) {
      result.has_lower = 1;
    } else {
      // other character is a special if all of the previous shit is not true
      result.has_symbol = 1;
    }
  }

  calculate_entropy(&result);
  determine_strength_level(&result);

  return result;
}

/*
entropy measures randomness/unpredictability
entropy = length * log2(pool_size)
- higher entropy harder to crack
- pool_size = number of all possible characters
*/
void calculate_entropy(password_strength_t *ps) {
  int pool_size = 0;

  if (ps->has_upper)
    pool_size += 26; // A-Z
  if (ps->has_lower)
    pool_size += 26; // a-z
  if (ps->has_digit)
    pool_size += 10; // 0-9
  if (ps->has_symbol)
    pool_size += 32; // common special characters

  // formula
  if (pool_size <= 0) {
    ps->entropy = 0.0;
  }
  ps->entropy = ps->length * (log(pool_size) / log(2));
}

/*
scoring logic based on:
- length (0-40 p)
- character variety (0-40 p)
- entropy (0-20 p)
total = 0-100 p
*/
void determine_strength_level(password_strength_t *ps) {
  ps->score = 0;

  // length scoring
  if (ps->length >= 16) {
    ps->score += 40;
  } else if (ps->length >= 12) {
    ps->score += 30;
  } else if (ps->length >= 8) {
    ps->score += 20;
  } else if (ps->length >= 6) {
    ps->score += 10;
  } else {
    ps->score += 5;
  }

  // character variaty
  int variaty = 0;
  if (ps->has_upper)
    variaty++;
  if (ps->has_lower)
    variaty++;
  if (ps->has_digit)
    variaty++;
  if (ps->has_symbol)
    variaty++;

  ps->score += variaty * 10;

  // entropy
  if (ps->entropy >= 60) {
    ps->score += 20;
  } else if (ps->entropy >= 40) {
    ps->score += 15;
  } else if (ps->entropy >= 28) {
    ps->score += 10;
  } else if (ps->entropy >= 20) {
    ps->score += 5;
  }

  ps->strength_score = ps->score;

  // determinite level based on score
  if (ps->score >= 85) {
    ps->level = VERY_STRONG;
  } else if (ps->score >= 70) {
    ps->level = STRONG;
  } else if (ps->score >= 50) {
    ps->level = MEDIUM;
  } else if (ps->score >= 30) {
    ps->level = WEAK;
  } else {
    ps->level = VERY_WEAK;
  }
}

// helper function
const char *level_to_string(strength_level_t level) {
  switch (level) {
  case NO_PASSWORD:
    return "No Password";
  case VERY_WEAK:
    return "Very Weak";
  case WEAK:
    return "Weak";
  case MEDIUM:
    return "Medium";
  case STRONG:
    return "Strong";
  case VERY_STRONG:
    return "Very Strong";
  default:
    return "Unknown";
  }
}

/*
TODO
- add common password detection
- add pattern detection
- add repetition detection
*/
