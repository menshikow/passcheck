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

/*
TODO
- parse the string
- interate through it
- update the struct fields
*/
PasswordStrength analyze_password(const char *ps) {}

/*
TODO
- implement entropy calculation
*/

void calculate_entropy(PasswordStrength *ps, const char *password) {}

/*
TODO
- scoring logic
*/
void determine_strength_level(PasswordStrength *ps) {}