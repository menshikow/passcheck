#ifndef COMPARISON_H
#define COMPARISON_H

#include <stdbool.h>

// similarity metrics
typedef struct {
  double similarity_score; // 0.0 to 1.0
  int edit_distance;
  bool is_similar; // true if similarity > threshold
  int common_chars;
  int common_positions;
} similarity_result_t;

// compare two passwords for similarity
similarity_result_t compare_passwords(const char *pw1, const char *pw2);

// check if passwords are too similar (for password change policies)
bool are_passwords_too_similar(const char *old_pw, const char *new_pw,
                               double threshold);

// calculate edit distance (Levenshtein)
int edit_distance(const char *s1, const char *s2);

#endif
