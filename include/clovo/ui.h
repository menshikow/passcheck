#ifndef UI_H
#define UI_H

#include "clovo/analyzer.h"

// ANSI color codes
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define DIM "\033[2m"

// Text colors
#define BLACK "\033[30m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"

// Background colors
#define BG_RED "\033[41m"
#define BG_GREEN "\033[42m"
#define BG_YELLOW "\033[43m"
#define BG_BLUE "\033[44m"

// Check if terminal supports colors
int supports_colors(void);

// Display password analysis results
void display_password_analysis(const password_strength_t *result);

// Display generated password with analysis
void display_generated_password(const char *password,
                                const password_strength_t *result);

// Display recommendations for weak passwords
void display_recommendations(const password_strength_t *result);

// Display a progress bar
void display_progress_bar(int score, int max, int width);

// Get color for strength level
const char *get_strength_color(strength_level_t level);

#endif
