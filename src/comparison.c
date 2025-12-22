#include "clovo/comparison.h"

#include <stdlib.h>
#include <string.h>

int edit_distance(const char *s1, const char *s2) {
  if (!s1 || !s2)
    return -1;

  int len1 = strlen(s1);
  int len2 = strlen(s2);

  if (len1 == 0)
    return len2;
  if (len2 == 0)
    return len1;

  // dynamic programming table
  int **dp = malloc((len1 + 1) * sizeof(int *));
  for (int i = 0; i <= len1; i++) {
    dp[i] = malloc((len2 + 1) * sizeof(int));
  }

  // initialize base cases
  for (int i = 0; i <= len1; i++) {
    dp[i][0] = i;
  }
  for (int j = 0; j <= len2; j++) {
    dp[0][j] = j;
  }

  // fill the table
  for (int i = 1; i <= len1; i++) {
    for (int j = 1; j <= len2; j++) {
      if (s1[i - 1] == s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        int min = dp[i - 1][j];
        if (dp[i][j - 1] < min)
          min = dp[i][j - 1];
        if (dp[i - 1][j - 1] < min)
          min = dp[i - 1][j - 1];
        dp[i][j] = min + 1;
      }
    }
  }

  int result = dp[len1][len2];

  // free memory
  for (int i = 0; i <= len1; i++) {
    free(dp[i]);
  }
  free(dp);

  return result;
}

similarity_result_t compare_passwords(const char *pw1, const char *pw2) {
  similarity_result_t result = {0};

  if (!pw1 || !pw2) {
    return result;
  }

  int len1 = strlen(pw1);
  int len2 = strlen(pw2);
  int max_len = len1 > len2 ? len1 : len2;

  if (max_len == 0) {
    result.similarity_score = 1.0;
    result.is_similar = true;
    return result;
  }

  // calculate edit distance
  result.edit_distance = edit_distance(pw1, pw2);

  // calculate similarity score (0.0 to 1.0)
  result.similarity_score = 1.0 - ((double)result.edit_distance / max_len);

  // count common characters
  int char_count1[256] = {0};
  int char_count2[256] = {0};

  for (int i = 0; pw1[i]; i++) {
    char_count1[(unsigned char)pw1[i]]++;
  }
  for (int i = 0; pw2[i]; i++) {
    char_count2[(unsigned char)pw2[i]]++;
  }

  for (int i = 0; i < 256; i++) {
    int min = char_count1[i] < char_count2[i] ? char_count1[i] : char_count2[i];
    result.common_chars += min;
  }

  // count common positions
  int min_len = len1 < len2 ? len1 : len2;
  for (int i = 0; i < min_len; i++) {
    if (pw1[i] == pw2[i]) {
      result.common_positions++;
    }
  }

  // consider similar if similarity > 0.7
  result.is_similar = (result.similarity_score > 0.7);

  return result;
}

bool are_passwords_too_similar(const char *old_pw, const char *new_pw,
                               double threshold) {
  if (!old_pw || !new_pw)
    return false;

  similarity_result_t result = compare_passwords(old_pw, new_pw);
  return result.similarity_score > threshold;
}
