#include "clovo/ui.h"
#include "clovo/analyzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

// check if terminal supports colors
int supports_colors(void) {
  const char *term = getenv("TERM");
  if (!term) {
    return 0;
  }
  
  // check if output is a tty
  if (!isatty(STDOUT_FILENO)) {
    return 0;
  }
  
  // check for common color-capable terminals
  if (strstr(term, "xterm") || strstr(term, "color") || 
      strstr(term, "256") || strstr(term, "ansi") ||
      strstr(term, "screen") || strstr(term, "tmux")) {
    return 1;
  }
  
  return 0;
}

// get color for strength level
const char *get_strength_color(strength_level_t level) {
  static int use_colors = -1;
  if (use_colors == -1) {
    use_colors = supports_colors();
  }
  
  if (!use_colors) {
    return "";
  }
  
  switch (level) {
    case NO_PASSWORD:
      return RED;
    case VERY_WEAK:
      return RED;
    case WEAK:
      return YELLOW;
    case MEDIUM:
      return YELLOW;
    case STRONG:
      return GREEN;
    case VERY_STRONG:
      return GREEN BOLD;
    default:
      return "";
  }
}

// display a progress bar
void display_progress_bar(int score, int max, int width) {
  static int use_colors = -1;
  if (use_colors == -1) {
    use_colors = supports_colors();
  }
  
  int filled = (score * width) / max;
  const char *color = "";
  const char *reset = use_colors ? RESET : "";
  
  // choose color based on score
  if (use_colors) {
    if (score >= 85) {
      color = GREEN;
    } else if (score >= 70) {
      color = GREEN;
    } else if (score >= 50) {
      color = YELLOW;
    } else if (score >= 30) {
      color = YELLOW;
    } else {
      color = RED;
    }
  }
  
  printf("  ");
  for (int i = 0; i < width; i++) {
    if (i < filled) {
      printf("%s█%s", color, reset);
    } else {
      printf("%s░%s", use_colors ? DIM : "", use_colors ? RESET : "");
    }
  }
  printf(" %d/%d\n", score, max);
}

void display_password_analysis(const password_strength_t *result) {
  if (!result) {
    return;
  }

  static int use_colors = -1;
  if (use_colors == -1) {
    use_colors = supports_colors();
  }

  const char *reset = use_colors ? RESET : "";
  const char *bold = use_colors ? BOLD : "";
  const char *dim = use_colors ? DIM : "";
  const char *strength_color = get_strength_color(result->level);
  
  // header
  printf("\n");
  if (use_colors) {
    printf("%s╔══════════════════════════════════════════════════════════╗%s\n", CYAN, reset);
    printf("%s║%s  %sPASSWORD ANALYSIS%s                                        %s║%s\n", 
           CYAN, reset, bold, reset, CYAN, reset);
    printf("%s╚══════════════════════════════════════════════════════════╝%s\n", CYAN, reset);
  } else {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  PASSWORD ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════\n");
  }
  
  printf("\n");
  
  // password characteristics
  printf("  %sCharacteristics:%s\n", bold, reset);
  printf("  ──────────────────────────────────────────────────────────\n");
  
  printf("  %sLength:%s           %s%3d%s characters\n", 
         dim, reset, bold, result->length, reset);
  
  printf("  %sCharacter types:%s\n", dim, reset);
  printf("    Lowercase:     %s%s%s\n", 
         result->has_lower ? (use_colors ? GREEN : "") : (use_colors ? RED : ""),
         result->has_lower ? "Yes" : "No",
         reset);
  printf("    Uppercase:     %s%s%s\n", 
         result->has_upper ? (use_colors ? GREEN : "") : (use_colors ? RED : ""),
         result->has_upper ? "Yes" : "No",
         reset);
  printf("    Digits:        %s%s%s\n", 
         result->has_digit ? (use_colors ? GREEN : "") : (use_colors ? RED : ""),
         result->has_digit ? "Yes" : "No",
         reset);
  printf("    Symbols:       %s%s%s\n", 
         result->has_symbol ? (use_colors ? GREEN : "") : (use_colors ? RED : ""),
         result->has_symbol ? "Yes" : "No",
         reset);
  
  printf("\n");
  printf("  %sSecurity metrics:%s\n", dim, reset);
  printf("  ──────────────────────────────────────────────────────────\n");
  printf("  %sEntropy:%s          %s%.1f%s bits\n", 
         dim, reset, bold, result->entropy, reset);
  printf("  %sCrack time:%s       %s%s%s\n", 
         dim, reset, bold, format_crack_time(result->crack_time_seconds), reset);
  
  printf("\n");
  
  // show pattern and weakness detection
  bool has_weaknesses = result->has_sequential_pattern || 
                        result->has_keyboard_pattern ||
                        result->has_repeated_chars ||
                        result->has_repeated_pattern ||
                        result->contains_dictionary_word;
  
  if (has_weaknesses) {
    printf("  %sWeaknesses detected:%s\n", dim, reset);
    printf("  ──────────────────────────────────────────────────────────\n");
    
    if (result->has_sequential_pattern) {
      printf("    %s- Sequential pattern found (e.g., 123, abc)%s\n",
             use_colors ? YELLOW : "", reset);
    }
    if (result->has_keyboard_pattern) {
      printf("    %s- Keyboard pattern found (e.g., qwerty, asdf)%s\n",
             use_colors ? YELLOW : "", reset);
    }
    if (result->has_repeated_chars) {
      printf("    %s- Repeated characters found (e.g., aaa, 111)%s\n",
             use_colors ? YELLOW : "", reset);
    }
    if (result->has_repeated_pattern) {
      printf("    %s- Repeated pattern found (e.g., abcabc)%s\n",
             use_colors ? YELLOW : "", reset);
    }
    if (result->contains_dictionary_word) {
      printf("    %s- Dictionary word detected%s\n",
             use_colors ? YELLOW : "", reset);
    }
    
    if (result->pattern_penalty > 0) {
      printf("    %s- Pattern penalty: -%d points%s\n",
             use_colors ? RED : "", result->pattern_penalty, reset);
    }
    
    printf("\n");
  }
  
  printf("  %sStrength Score:%s\n", dim, reset);
  display_progress_bar(result->strength_score, 100, 40);
  
  printf("\n");
  printf("  %sRating:%s          %s%s%s%s\n", 
         dim, reset, strength_color, bold, level_to_string(result->level), reset);
  
  printf("\n");
  
  // feedback message
  if (result->level == VERY_STRONG || result->level == STRONG) {
    if (use_colors) {
      printf("  %s%sExcellent password! This password is highly secure.%s\n", 
             GREEN, bold, reset);
    } else {
      printf("  Excellent password! This password is highly secure.\n");
    }
  } else {
    display_recommendations(result);
  }
  
  printf("\n");
}

void display_generated_password(const char *password, const password_strength_t *result) {
  if (!password || !result) {
    return;
  }

  static int use_colors = -1;
  if (use_colors == -1) {
    use_colors = supports_colors();
  }

  const char *reset = use_colors ? RESET : "";
  const char *bold = use_colors ? BOLD : "";
  const char *dim = use_colors ? DIM : "";
  const char *strength_color = get_strength_color(result->level);
  
  // header
  printf("\n");
  if (use_colors) {
    printf("%s╔══════════════════════════════════════════════════════════╗%s\n", CYAN, reset);
    printf("%s║%s  %sGENERATED PASSWORD%s                                      %s║%s\n", 
           CYAN, reset, bold, reset, CYAN, reset);
    printf("%s╚══════════════════════════════════════════════════════════╝%s\n", CYAN, reset);
  } else {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  GENERATED PASSWORD\n");
    printf("═══════════════════════════════════════════════════════════\n");
  }
  
  printf("\n");
  
  // password display with highlight
  printf("  %sPassword:%s\n", dim, reset);
  if (use_colors) {
    printf("  %s%s%s%s%s\n", BOLD, CYAN, password, reset, reset);
  } else {
    printf("  %s\n", password);
  }
  
  // show length
  printf("  %sLength:%s           %s%zu%s characters\n", 
         dim, reset, bold, strlen(password), reset);
  
  printf("\n");
  printf("  %sStrength Score:%s\n", dim, reset);
  display_progress_bar(result->strength_score, 100, 40);
  
  printf("\n");
  printf("  %sRating:%s          %s%s%s%s\n", 
         dim, reset, strength_color, bold, level_to_string(result->level), reset);
  
  if (use_colors) {
    printf("\n  %s%sPassword generated successfully!%s\n", GREEN, bold, reset);
  } else {
    printf("\n  Password generated successfully!\n");
  }
  
  printf("\n");
}

void display_recommendations(const password_strength_t *result) {
  if (!result) {
    return;
  }

  static int use_colors = -1;
  if (use_colors == -1) {
    use_colors = supports_colors();
  }

  const char *reset = use_colors ? RESET : "";
  const char *bold = use_colors ? BOLD : "";
  const char *warning_color = use_colors ? YELLOW : "";
  
  int has_recommendations = 0;
  
  if (result->length < 8 || result->length < 12 || 
      !result->has_upper || !result->has_digit || 
      !result->has_symbol || !result->has_lower) {
    has_recommendations = 1;
  }
  
  if (!has_recommendations) {
    return;
  }
  
  if (use_colors) {
    printf("  %s%sRecommendations:%s\n", warning_color, bold, reset);
  } else {
    printf("  Recommendations:\n");
  }
  printf("  ──────────────────────────────────────────────────────────\n");
  
  if (result->length < 8) {
    printf("    %s- Use at least 8 characters for basic security%s\n", 
           use_colors ? YELLOW : "", reset);
  } else if (result->length < 12) {
    printf("    %s- Consider using 12+ characters for better security%s\n", 
           use_colors ? YELLOW : "", reset);
  }
  
  if (!result->has_upper) {
    printf("    %s- Add uppercase letters (A-Z)%s\n", 
           use_colors ? YELLOW : "", reset);
  }
  
  if (!result->has_digit) {
    printf("    %s- Add numbers (0-9)%s\n", 
           use_colors ? YELLOW : "", reset);
  }
  
  if (!result->has_symbol) {
    printf("    %s- Add symbols (!@#$%%^&* etc.)%s\n", 
           use_colors ? YELLOW : "", reset);
  }
  
  if (!result->has_lower) {
    printf("    %s- Add lowercase letters (a-z)%s\n", 
           use_colors ? YELLOW : "", reset);
  }
  
  printf("\n");
}
