#include "clovo/export.h"
#include "clovo/analyzer.h"

#include <stdio.h>
#include <string.h>

int export_analysis_stdout(const password_strength_t *result,
                           const char *password, export_format_t format) {
  if (!result || !password)
    return -1;

  switch (format) {
  case EXPORT_JSON:
    printf("{\n");
    printf("  \"password\": \"%s\",\n", password);
    printf("  \"length\": %d,\n", result->length);
    printf("  \"entropy\": %.2f,\n", result->entropy);
    printf("  \"crack_time_seconds\": %.2f,\n", result->crack_time_seconds);
    printf("  \"crack_time\": \"%s\",\n",
           format_crack_time(result->crack_time_seconds));
    printf("  \"score\": %d,\n", result->strength_score);
    printf("  \"rating\": \"%s\",\n", level_to_string(result->level));
    printf("  \"has_lowercase\": %s,\n", result->has_lower ? "true" : "false");
    printf("  \"has_uppercase\": %s,\n", result->has_upper ? "true" : "false");
    printf("  \"has_digits\": %s,\n", result->has_digit ? "true" : "false");
    printf("  \"has_symbols\": %s,\n", result->has_symbol ? "true" : "false");
    printf("  \"has_sequential_pattern\": %s,\n",
           result->has_sequential_pattern ? "true" : "false");
    printf("  \"has_keyboard_pattern\": %s,\n",
           result->has_keyboard_pattern ? "true" : "false");
    printf("  \"has_repeated_chars\": %s,\n",
           result->has_repeated_chars ? "true" : "false");
    printf("  \"has_repeated_pattern\": %s,\n",
           result->has_repeated_pattern ? "true" : "false");
    printf("  \"contains_dictionary_word\": %s,\n",
           result->contains_dictionary_word ? "true" : "false");
    printf("  \"pattern_penalty\": %d\n", result->pattern_penalty);
    printf("}\n");
    break;

  case EXPORT_CSV:
    printf(
        "password,length,entropy,crack_time_seconds,crack_time,score,rating,");
    printf("has_lowercase,has_uppercase,has_digits,has_symbols,");
    printf("has_sequential_pattern,has_keyboard_pattern,has_repeated_chars,");
    printf("has_repeated_pattern,contains_dictionary_word,pattern_penalty\n");
    printf("\"%s\",%d,%.2f,%.2f,\"%s\",%d,\"%s\",", password, result->length,
           result->entropy, result->crack_time_seconds,
           format_crack_time(result->crack_time_seconds),
           result->strength_score, level_to_string(result->level));
    printf("%s,%s,%s,%s,", result->has_lower ? "true" : "false",
           result->has_upper ? "true" : "false",
           result->has_digit ? "true" : "false",
           result->has_symbol ? "true" : "false");
    printf("%s,%s,%s,%s,%s,%d\n",
           result->has_sequential_pattern ? "true" : "false",
           result->has_keyboard_pattern ? "true" : "false",
           result->has_repeated_chars ? "true" : "false",
           result->has_repeated_pattern ? "true" : "false",
           result->contains_dictionary_word ? "true" : "false",
           result->pattern_penalty);
    break;

  case EXPORT_TEXT:
  default:
    // fall back to regular display
    return 0;
  }

  return 0;
}

int export_analysis(const password_strength_t *result, const char *password,
                    const char *filename, export_format_t format) {
  if (!result || !password || !filename)
    return -1;

  FILE *file = fopen(filename, "w");
  if (!file)
    return -1;

  // redirect stdout temporarily
  FILE *old_stdout = stdout;
  stdout = file;

  int ret = export_analysis_stdout(result, password, format);

  fclose(file);
  stdout = old_stdout;

  return ret;
}

int export_batch_results(const password_strength_t *results,
                         const char **passwords, int count,
                         const char *filename, export_format_t format) {
  if (!results || !passwords || count <= 0 || !filename)
    return -1;

  FILE *file = fopen(filename, "w");
  if (!file)
    return -1;

  FILE *old_stdout = stdout;
  stdout = file;

  if (format == EXPORT_JSON) {
    printf("[\n");
    for (int i = 0; i < count; i++) {
      export_analysis_stdout(&results[i], passwords[i], EXPORT_JSON);
      if (i < count - 1)
        printf(",");
      printf("\n");
    }
    printf("]\n");
  } else if (format == EXPORT_CSV) {
    // header (only once)
    printf(
        "password,length,entropy,crack_time_seconds,crack_time,score,rating,");
    printf("has_lowercase,has_uppercase,has_digits,has_symbols,");
    printf("has_sequential_pattern,has_keyboard_pattern,has_repeated_chars,");
    printf("has_repeated_pattern,contains_dictionary_word,pattern_penalty\n");
    // data rows (without header)
    for (int i = 0; i < count; i++) {
      printf("\"%s\",%d,%.2f,%.2f,\"%s\",%d,\"%s\",", passwords[i],
             results[i].length, results[i].entropy,
             results[i].crack_time_seconds,
             format_crack_time(results[i].crack_time_seconds),
             results[i].strength_score, level_to_string(results[i].level));
      printf("%s,%s,%s,%s,", results[i].has_lower ? "true" : "false",
             results[i].has_upper ? "true" : "false",
             results[i].has_digit ? "true" : "false",
             results[i].has_symbol ? "true" : "false");
      printf("%s,%s,%s,%s,%s,%d\n",
             results[i].has_sequential_pattern ? "true" : "false",
             results[i].has_keyboard_pattern ? "true" : "false",
             results[i].has_repeated_chars ? "true" : "false",
             results[i].has_repeated_pattern ? "true" : "false",
             results[i].contains_dictionary_word ? "true" : "false",
             results[i].pattern_penalty);
    }
  }

  fclose(file);
  stdout = old_stdout;

  return 0;
}
