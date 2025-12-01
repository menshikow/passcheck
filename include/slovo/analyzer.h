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
} password_strength_t;

password_strength_t analyze_password(const char *ps);

void calculate_entropy(password_strength_t *ps);
void determine_strength_level(password_strength_t *ps);

const char *level_to_string(password_strength_t level);

#endif
