#ifndef ANALYZER_H
#define ANALYZER_H
#include <stdbool.h>

typedef enum {
  NO_PASSWORD,
  VERY_WEAK,
  WEAK,
  MEDIUM,
  STRONG,
  VERY_STRONG
} strength_level_t;

typedef struct {
  int score;
  int strength_score;
  int length;
  double entropy;
  bool has_lower;
  bool has_upper;
  bool has_digit;
  bool has_symbol;
  strength_level_t level;

  // new analysis fields
  bool has_sequential_pattern;
  bool has_keyboard_pattern;
  bool has_repeated_chars;
  bool has_repeated_pattern;
  bool contains_dictionary_word;
  bool contains_leetspeak;
  bool contains_personal_info;
  int pattern_penalty;
  double crack_time_seconds;
} password_strength_t;

password_strength_t analyze_password(const char *ps);

void calculate_entropy(password_strength_t *ps);
void determine_strength_level(password_strength_t *ps);
void detect_patterns(password_strength_t *ps, const char *password);
void detect_repetitions(password_strength_t *ps, const char *password);
void check_dictionary_words(password_strength_t *ps, const char *password);
void detect_leetspeak(password_strength_t *ps, const char *password);
void detect_personal_info(password_strength_t *ps, const char *password,
                          const char *user_info);
void estimate_crack_time(password_strength_t *ps);

const char *level_to_string(strength_level_t level);
const char *format_crack_time(double seconds);

#endif
