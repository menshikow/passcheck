#include "clovo/analyzer.h"

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

// common dictionary words to check for
static const char *common_words[] = {
    "password", "admin",    "welcome",  "login",   "qwerty",   "abc123",
    "monkey",   "dragon",   "master",   "letmein", "trustno1", "sunshine",
    "princess", "football", "baseball", "shadow",  "superman", "batman",
    "computer", "internet", "hello",    "love",    "secret",   "test",
    "user",     "root",     "guest",    "system",  "service",  "account",
    "access",   "security", NULL};

// keyboard patterns (horizontal sequences)
static const char *keyboard_patterns[] = {
    "qwerty",   "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl",
    "zxcvbnm",  "123456", "654321", "qwerty123",  "1qaz2wsx",
    "1q2w3e4r", "qwe123", NULL};

// check if string contains a sequential pattern (123, abc, etc)
static bool has_sequential(const char *str, int len) {
  if (len < 3)
    return false;

  for (int i = 0; i <= len - 3; i++) {
    // check forward sequences
    if (isdigit(str[i]) && isdigit(str[i + 1]) && isdigit(str[i + 2])) {
      int diff1 = str[i + 1] - str[i];
      int diff2 = str[i + 2] - str[i + 1];
      if (diff1 == diff2 && (diff1 == 1 || diff1 == -1)) {
        return true;
      }
    }
    // check letter sequences
    if (isalpha(str[i]) && isalpha(str[i + 1]) && isalpha(str[i + 2])) {
      char c1 = tolower(str[i]);
      char c2 = tolower(str[i + 1]);
      char c3 = tolower(str[i + 2]);
      if (c2 - c1 == 1 && c3 - c2 == 1) {
        return true;
      }
    }
  }
  return false;
}

// check if string contains keyboard pattern
static bool has_keyboard_pattern(const char *str) {
  char lower[256];
  int len = strlen(str);
  if (len >= 256)
    len = 255;

  for (int i = 0; i < len; i++) {
    lower[i] = tolower((unsigned char)str[i]);
  }
  lower[len] = '\0';

  for (int i = 0; keyboard_patterns[i] != NULL; i++) {
    if (strstr(lower, keyboard_patterns[i]) != NULL) {
      return true;
    }
  }
  return false;
}

// check for repeated characters (aaa, 111, etc)
static bool has_repeated_chars(const char *str, int len) {
  if (len < 3)
    return false;

  for (int i = 0; i <= len - 3; i++) {
    if (str[i] == str[i + 1] && str[i + 1] == str[i + 2]) {
      return true;
    }
  }
  return false;
}

// check for repeated patterns (abcabc, 123123, etc)
static bool has_repeated_pattern(const char *str, int len) {
  if (len < 4)
    return false;

  // check for patterns of length 2-6
  for (int pattern_len = 2; pattern_len <= len / 2 && pattern_len <= 6;
       pattern_len++) {
    for (int start = 0; start <= len - (pattern_len * 2); start++) {
      bool match = true;
      for (int i = 0; i < pattern_len; i++) {
        if (str[start + i] != str[start + pattern_len + i]) {
          match = false;
          break;
        }
      }
      if (match) {
        return true;
      }
    }
  }
  return false;
}

// check if password contains dictionary words (made non-static for use in
// leetspeak detection)
static bool contains_dictionary_word_internal(const char *str);

static bool contains_dictionary_word_internal(const char *str) {
  char lower[256];
  int len = strlen(str);
  if (len >= 256)
    len = 255;

  for (int i = 0; i < len; i++) {
    lower[i] = tolower((unsigned char)str[i]);
  }
  lower[len] = '\0';

  for (int i = 0; common_words[i] != NULL; i++) {
    if (strstr(lower, common_words[i]) != NULL) {
      return true;
    }
  }
  return false;
}

void detect_patterns(password_strength_t *ps, const char *password) {
  if (!ps || !password)
    return;

  ps->has_sequential_pattern = has_sequential(password, ps->length);
  ps->has_keyboard_pattern = has_keyboard_pattern(password);

  // apply penalty for patterns
  if (ps->has_sequential_pattern) {
    ps->pattern_penalty += 15;
  }
  if (ps->has_keyboard_pattern) {
    ps->pattern_penalty += 20;
  }
}

void detect_repetitions(password_strength_t *ps, const char *password) {
  if (!ps || !password)
    return;

  ps->has_repeated_chars = has_repeated_chars(password, ps->length);
  ps->has_repeated_pattern = has_repeated_pattern(password, ps->length);

  // apply penalty for repetitions
  if (ps->has_repeated_chars) {
    ps->pattern_penalty += 10;
  }
  if (ps->has_repeated_pattern) {
    ps->pattern_penalty += 15;
  }
}

void check_dictionary_words(password_strength_t *ps, const char *password) {
  if (!ps || !password)
    return;

  ps->contains_dictionary_word = contains_dictionary_word_internal(password);

  // apply penalty for dictionary words
  if (ps->contains_dictionary_word) {
    ps->pattern_penalty += 25;
  }
}

// estimate time to crack password (in seconds)
// based on entropy and common attack speeds
void estimate_crack_time(password_strength_t *ps) {
  if (!ps)
    return;

  // assume attacker can try 1 billion combinations per second (1e9)
  // this is reasonable for modern hardware with gpu acceleration
  double attempts_per_second = 1e9;

  // total possible combinations = 2^entropy
  double total_combinations = pow(2.0, ps->entropy);

  // average time to crack = total_combinations / (2 * attempts_per_second)
  // divide by 2 because on average you find it halfway through
  ps->crack_time_seconds = total_combinations / (2.0 * attempts_per_second);

  // if entropy is very low, set minimum time
  if (ps->entropy < 10) {
    ps->crack_time_seconds = 0.001; // milliseconds
  }
}

// format crack time in human readable format
const char *format_crack_time(double seconds) {
  static char buffer[128];

  if (seconds < 1.0) {
    snprintf(buffer, sizeof(buffer), "instant");
    return buffer;
  }

  if (seconds < 60.0) {
    snprintf(buffer, sizeof(buffer), "%.1f seconds", seconds);
    return buffer;
  }

  double minutes = seconds / 60.0;
  if (minutes < 60.0) {
    snprintf(buffer, sizeof(buffer), "%.1f minutes", minutes);
    return buffer;
  }

  double hours = minutes / 60.0;
  if (hours < 24.0) {
    snprintf(buffer, sizeof(buffer), "%.1f hours", hours);
    return buffer;
  }

  double days = hours / 24.0;
  if (days < 365.0) {
    snprintf(buffer, sizeof(buffer), "%.1f days", days);
    return buffer;
  }

  double years = days / 365.0;
  if (years < 1000.0) {
    snprintf(buffer, sizeof(buffer), "%.1f years", years);
    return buffer;
  }

  double millennia = years / 1000.0;
  if (millennia < 1000000.0) {
    snprintf(buffer, sizeof(buffer), "%.1f millennia", millennia);
  } else {
    // for extremely large values, use scientific notation
    snprintf(buffer, sizeof(buffer), "%.2e years", years);
  }
  return buffer;
}

password_strength_t analyze_password(const char *ps) {
  password_strength_t result = {0};

  if (ps == NULL) {
    result.level = NO_PASSWORD;
    return result;
  }

  // iterate through the string until the end
  for (int i = 0; ps[i] != '\0'; i++) {
    result.length++;
    if (isupper(ps[i])) {
      result.has_upper = 1;
    } else if (isdigit(ps[i])) {
      result.has_digit = 1;
    } else if (islower(ps[i])) {
      result.has_lower = 1;
    } else {
      // if it's not upper, digit, or lower, it must be a symbol
      result.has_symbol = 1;
    }
  }

  // detect patterns and weaknesses
  detect_patterns(&result, ps);
  detect_repetitions(&result, ps);
  check_dictionary_words(&result, ps);
  detect_leetspeak(&result, ps);

  calculate_entropy(&result);
  estimate_crack_time(&result);
  determine_strength_level(&result);

  return result;
}

/*
entropy measures randomness/unpredictability
entropy = length * log2(pool_size)
higher entropy = harder to crack
pool_size = number of all possible characters we can use
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

  // calculate entropy using the formula
  if (pool_size <= 0) {
    ps->entropy = 0.0;
    return;
  }
  ps->entropy = ps->length * (log(pool_size) / log(2));
}

/*
scoring logic:
- length gives 0-40 points
- character variety gives 0-40 points
- entropy gives 0-20 points
- pattern penalties reduce score (up to -35 points)
total = 0-100 points (can go negative, but we cap at 0)
*/
void determine_strength_level(password_strength_t *ps) {
  ps->score = 0;

  // score based on length
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

  // score based on character variety
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

  // score based on entropy
  if (ps->entropy >= 60) {
    ps->score += 20;
  } else if (ps->entropy >= 40) {
    ps->score += 15;
  } else if (ps->entropy >= 28) {
    ps->score += 10;
  } else if (ps->entropy >= 20) {
    ps->score += 5;
  }

  // apply pattern penalties
  ps->score -= ps->pattern_penalty;
  if (ps->score < 0) {
    ps->score = 0;
  }

  ps->strength_score = ps->score;

  // determine strength level based on final score
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

// detect leetspeak patterns (P@ssw0rd -> password)
void detect_leetspeak(password_strength_t *ps, const char *password) {
  if (!ps || !password)
    return;

  // common leetspeak substitutions
  char normalized[256];
  int len = strlen(password);
  if (len >= 256)
    len = 255;

  for (int i = 0; i < len; i++) {
    char c = tolower((unsigned char)password[i]);
    switch (c) {
    case '0':
      normalized[i] = 'o';
      break;
    case '1':
      normalized[i] = 'l';
      break;
    case '3':
      normalized[i] = 'e';
      break;
    case '4':
      normalized[i] = 'a';
      break;
    case '5':
      normalized[i] = 's';
      break;
    case '7':
      normalized[i] = 't';
      break;
    case '@':
      normalized[i] = 'a';
      break;
    case '$':
      normalized[i] = 's';
      break;
    case '!':
      normalized[i] = 'i';
      break;
    default:
      normalized[i] = c;
      break;
    }
  }
  normalized[len] = '\0';

  // check if normalized version contains dictionary words
  if (contains_dictionary_word_internal(normalized)) {
    ps->contains_leetspeak = true;
    ps->pattern_penalty += 15;
  }
}

// detect personal information (dates, common names, etc.)
void detect_personal_info(password_strength_t *ps, const char *password,
                          const char *user_info) {
  if (!ps || !password)
    return;

  ps->contains_personal_info = false;

  if (!user_info || strlen(user_info) == 0)
    return;

  // simple check: see if password contains user info
  char lower_pw[256];
  char lower_info[256];
  int pw_len = strlen(password);
  int info_len = strlen(user_info);

  if (pw_len >= 256)
    pw_len = 255;
  if (info_len >= 256)
    info_len = 255;

  for (int i = 0; i < pw_len; i++) {
    lower_pw[i] = tolower((unsigned char)password[i]);
  }
  lower_pw[pw_len] = '\0';

  for (int i = 0; i < info_len; i++) {
    lower_info[i] = tolower((unsigned char)user_info[i]);
  }
  lower_info[info_len] = '\0';

  // check if password contains user info
  if (strstr(lower_pw, lower_info) != NULL) {
    ps->contains_personal_info = true;
    ps->pattern_penalty += 20;
  }
}

// convert strength level enum to string
const char *level_to_string(strength_level_t level) {
  switch (level) {
  case NO_PASSWORD:
    return "NO PASSWORD";
  case VERY_WEAK:
    return "VERY WEAK";
  case WEAK:
    return "WEAK";
  case MEDIUM:
    return "MEDIUM";
  case STRONG:
    return "STRONG";
  case VERY_STRONG:
    return "VERY STRONG";
  default:
    return "UNKNOWN";
  }
}
