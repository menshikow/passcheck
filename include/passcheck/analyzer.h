#include <stdbool.h>

typedef struct {
  int score;
  int length;
  double entropy;
  bool has_lower;
  bool has_upper;
  bool has_digit;
  bool has_symbol;
  char level[20];
} PasswordStrength;

PasswordStrength analyze_password(const char *ps);

void calculate_entropy(PasswordStrength *ps, const char *password);
void determine_strength_level(PasswordStrength *ps);