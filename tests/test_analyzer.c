#include "slovo/analyzer.h"
#include "unity.h"
#include <string.h>

// setUp and tearDown run before/after each test
void setUp(void) {
  // Optional: Initialize test fixtures
}

void tearDown(void) {
  // Optional: Clean up after tests
}

// ============================================
// NULL/Empty Password Tests
// ============================================

void test_null_password(void) {
  password_strength_t result = analyze_password(NULL);

  TEST_ASSERT_EQUAL(0, result.length);
  TEST_ASSERT_EQUAL(NO_PASSWORD, result.level);
  TEST_ASSERT_EQUAL(0, result.score);
}

void test_empty_password(void) {
  password_strength_t result = analyze_password("");

  TEST_ASSERT_EQUAL(0, result.length);
  TEST_ASSERT_EQUAL(VERY_WEAK, result.level);
}

// ============================================
// Character Detection Tests
// ============================================

void test_lowercase_only(void) {
  password_strength_t result = analyze_password("abcdef");

  TEST_ASSERT_TRUE(result.has_lower);
  TEST_ASSERT_FALSE(result.has_upper);
  TEST_ASSERT_FALSE(result.has_digit);
  TEST_ASSERT_FALSE(result.has_symbol);
  TEST_ASSERT_EQUAL(6, result.length);
}

void test_uppercase_only(void) {
  password_strength_t result = analyze_password("ABCDEF");

  TEST_ASSERT_FALSE(result.has_lower);
  TEST_ASSERT_TRUE(result.has_upper);
  TEST_ASSERT_FALSE(result.has_digit);
  TEST_ASSERT_FALSE(result.has_symbol);
  TEST_ASSERT_EQUAL(6, result.length);
}

void test_digits_only(void) {
  password_strength_t result = analyze_password("123456");

  TEST_ASSERT_FALSE(result.has_lower);
  TEST_ASSERT_FALSE(result.has_upper);
  TEST_ASSERT_TRUE(result.has_digit);
  TEST_ASSERT_FALSE(result.has_symbol);
  TEST_ASSERT_EQUAL(6, result.length);
}

void test_symbols_only(void) {
  password_strength_t result = analyze_password("!@#$%^");

  TEST_ASSERT_FALSE(result.has_lower);
  TEST_ASSERT_FALSE(result.has_upper);
  TEST_ASSERT_FALSE(result.has_digit);
  TEST_ASSERT_TRUE(result.has_symbol);
  TEST_ASSERT_EQUAL(6, result.length);
}

void test_mixed_characters(void) {
  password_strength_t result = analyze_password("Abc123!@#");

  TEST_ASSERT_TRUE(result.has_lower);
  TEST_ASSERT_TRUE(result.has_upper);
  TEST_ASSERT_TRUE(result.has_digit);
  TEST_ASSERT_TRUE(result.has_symbol);
  TEST_ASSERT_EQUAL(9, result.length);
}

// ============================================
// Length Tests
// ============================================

void test_short_password(void) {
  password_strength_t result = analyze_password("abc");

  TEST_ASSERT_EQUAL(3, result.length);
  TEST_ASSERT_LESS_THAN(20, result.score);
}

void test_medium_length_password(void) {
  password_strength_t result = analyze_password("abcdefgh");

  TEST_ASSERT_EQUAL(8, result.length);
  TEST_ASSERT_GREATER_OR_EQUAL(20, result.score);
}

void test_long_password(void) {
  password_strength_t result = analyze_password("abcdefghijklmnop");

  TEST_ASSERT_EQUAL(16, result.length);
  TEST_ASSERT_GREATER_OR_EQUAL(40, result.score);
}

// ============================================
// Entropy Tests
// ============================================

void test_entropy_single_character_type(void) {
  // Only lowercase: pool_size = 26
  password_strength_t result = analyze_password("abcdefgh");

  // Entropy = 8 * log2(26) ≈ 37.6
  TEST_ASSERT_GREATER_THAN(35.0, result.entropy);
  TEST_ASSERT_LESS_THAN(40.0, result.entropy);
}

void test_entropy_mixed_characters(void) {
  // Lower + Upper + Digit + Symbol: pool_size = 94
  password_strength_t result = analyze_password("Abc123!@#");

  // Entropy = 9 * log2(94) ≈ 59.1
  TEST_ASSERT_GREATER_THAN(55.0, result.entropy);
  TEST_ASSERT_LESS_THAN(65.0, result.entropy);
}

void test_entropy_zero_for_empty(void) {
  password_strength_t result = analyze_password("");

  TEST_ASSERT_EQUAL_DOUBLE(0.0, result.entropy);
}

// ============================================
// Strength Level Tests
// ============================================

void test_very_weak_password(void) {
  password_strength_t result = analyze_password("abc");

  TEST_ASSERT_EQUAL(VERY_WEAK, result.level);
  TEST_ASSERT_LESS_THAN(30, result.score);
}

void test_weak_password(void) {
  password_strength_t result = analyze_password("password");

  TEST_ASSERT_EQUAL(WEAK, result.level);
  TEST_ASSERT_GREATER_OR_EQUAL(30, result.score);
  TEST_ASSERT_LESS_THAN(50, result.score);
}

void test_medium_password(void) {
  password_strength_t result = analyze_password("Password1");

  TEST_ASSERT_EQUAL(MEDIUM, result.level);
  TEST_ASSERT_GREATER_OR_EQUAL(50, result.score);
  TEST_ASSERT_LESS_THAN(70, result.score);
}

void test_strong_password(void) {
  password_strength_t result = analyze_password("P@ssw0rd123");

  TEST_ASSERT_EQUAL(STRONG, result.level);
  TEST_ASSERT_GREATER_OR_EQUAL(70, result.score);
  TEST_ASSERT_LESS_THAN(85, result.score);
}

void test_very_strong_password(void) {
  password_strength_t result = analyze_password("MyS3cur3P@ssw0rd!");

  TEST_ASSERT_EQUAL(VERY_STRONG, result.level);
  TEST_ASSERT_GREATER_OR_EQUAL(85, result.score);
}

// ============================================
// Scoring Tests
// ============================================

void test_score_increases_with_length(void) {
  password_strength_t short_pw = analyze_password("Abc1!");
  password_strength_t long_pw = analyze_password("Abc1!Abc1!Abc1!");

  TEST_ASSERT_GREATER_THAN(short_pw.score, long_pw.score);
}

void test_score_increases_with_variety(void) {
  password_strength_t low_variety = analyze_password("aaaaaaaa");
  password_strength_t high_variety = analyze_password("Aa1!Aa1!");

  TEST_ASSERT_GREATER_THAN(low_variety.score, high_variety.score);
}

void test_score_calculation_length_16plus(void) {
  password_strength_t result = analyze_password("aaaaaaaaaaaaaaaa"); // 16 chars

  // Should get 40 points for length alone
  TEST_ASSERT_GREATER_OR_EQUAL(40, result.score);
}

void test_score_calculation_all_types(void) {
  // Password with all character types
  password_strength_t result = analyze_password("Abc123!@");

  // Should have points from all variety types (4 * 10 = 40)
  TEST_ASSERT_GREATER_OR_EQUAL(40, result.score);
}

// ============================================
// Helper Function Tests
// ============================================

void test_level_to_string_no_password(void) {
  TEST_ASSERT_EQUAL_STRING("No Password", level_to_string(NO_PASSWORD));
}

void test_level_to_string_very_weak(void) {
  TEST_ASSERT_EQUAL_STRING("Very Weak", level_to_string(VERY_WEAK));
}

void test_level_to_string_weak(void) {
  TEST_ASSERT_EQUAL_STRING("Weak", level_to_string(WEAK));
}

void test_level_to_string_medium(void) {
  TEST_ASSERT_EQUAL_STRING("Medium", level_to_string(MEDIUM));
}

void test_level_to_string_strong(void) {
  TEST_ASSERT_EQUAL_STRING("Strong", level_to_string(STRONG));
}

void test_level_to_string_very_strong(void) {
  TEST_ASSERT_EQUAL_STRING("Very Strong", level_to_string(VERY_STRONG));
}

// ============================================
// Edge Case Tests
// ============================================

void test_whitespace_in_password(void) {
  password_strength_t result = analyze_password("pass word");

  TEST_ASSERT_EQUAL(9, result.length);
  TEST_ASSERT_TRUE(result.has_symbol); // Space is treated as symbol
}

void test_special_characters_variety(void) {
  password_strength_t result = analyze_password("!@#$%^&*()");

  TEST_ASSERT_TRUE(result.has_symbol);
  TEST_ASSERT_EQUAL(10, result.length);
}

void test_very_long_password(void) {
  char long_pw[101];
  memset(long_pw, 'a', 100);
  long_pw[100] = '\0';

  password_strength_t result = analyze_password(long_pw);

  TEST_ASSERT_EQUAL(100, result.length);
  TEST_ASSERT_GREATER_OR_EQUAL(40, result.score); // Max length points
}

void test_numbers_at_end(void) {
  password_strength_t result = analyze_password("password123");

  TEST_ASSERT_TRUE(result.has_lower);
  TEST_ASSERT_TRUE(result.has_digit);
  TEST_ASSERT_EQUAL(11, result.length);
}

void test_special_chars_at_start(void) {
  password_strength_t result = analyze_password("!@#password");

  TEST_ASSERT_TRUE(result.has_symbol);
  TEST_ASSERT_TRUE(result.has_lower);
  TEST_ASSERT_EQUAL(11, result.length);
}

// ============================================
// Real-World Password Tests
// ============================================

void test_common_weak_password_password(void) {
  password_strength_t result = analyze_password("password");
  TEST_ASSERT_LESS_THAN(50, result.score);
}

void test_common_weak_password_123456(void) {
  password_strength_t result = analyze_password("123456");
  TEST_ASSERT_LESS_THAN(50, result.score);
}

void test_common_weak_password_qwerty(void) {
  password_strength_t result = analyze_password("qwerty");
  TEST_ASSERT_LESS_THAN(50, result.score);
}

void test_common_weak_password_abc123(void) {
  password_strength_t result = analyze_password("abc123");
  TEST_ASSERT_LESS_THAN(50, result.score);
}

void test_strong_password_example1(void) {
  password_strength_t result = analyze_password("MyS3cur3P@ssw0rd!");
  TEST_ASSERT_GREATER_OR_EQUAL(70, result.score);
}

void test_strong_password_example2(void) {
  password_strength_t result = analyze_password("Tr0ub4dor&3");
  TEST_ASSERT_GREATER_OR_EQUAL(70, result.score);
}

void test_strong_password_example3(void) {
  password_strength_t result = analyze_password("C0mpl3x!ty#2024");
  TEST_ASSERT_GREATER_OR_EQUAL(70, result.score);
}

// ============================================
// Boundary Tests
// ============================================

void test_exactly_8_characters(void) {
  password_strength_t result = analyze_password("abcdefgh");
  TEST_ASSERT_EQUAL(8, result.length);
}

void test_exactly_12_characters(void) {
  password_strength_t result = analyze_password("abcdefghijkl");
  TEST_ASSERT_EQUAL(12, result.length);
}

void test_exactly_16_characters(void) {
  password_strength_t result = analyze_password("abcdefghijklmnop");
  TEST_ASSERT_EQUAL(16, result.length);
}

void test_single_character(void) {
  password_strength_t result = analyze_password("a");
  TEST_ASSERT_EQUAL(1, result.length);
  TEST_ASSERT_EQUAL(VERY_WEAK, result.level);
}

// ============================================
// Main Test Runner
// ============================================

int main(void) {
  UNITY_BEGIN();

  // NULL/Empty tests
  RUN_TEST(test_null_password);
  RUN_TEST(test_empty_password);

  // Character detection tests
  RUN_TEST(test_lowercase_only);
  RUN_TEST(test_uppercase_only);
  RUN_TEST(test_digits_only);
  RUN_TEST(test_symbols_only);
  RUN_TEST(test_mixed_characters);

  // Length tests
  RUN_TEST(test_short_password);
  RUN_TEST(test_medium_length_password);
  RUN_TEST(test_long_password);

  // Entropy tests
  RUN_TEST(test_entropy_single_character_type);
  RUN_TEST(test_entropy_mixed_characters);
  RUN_TEST(test_entropy_zero_for_empty);

  // Strength level tests
  RUN_TEST(test_very_weak_password);
  RUN_TEST(test_weak_password);
  RUN_TEST(test_medium_password);
  RUN_TEST(test_strong_password);
  RUN_TEST(test_very_strong_password);

  // Scoring tests
  RUN_TEST(test_score_increases_with_length);
  RUN_TEST(test_score_increases_with_variety);
  RUN_TEST(test_score_calculation_length_16plus);
  RUN_TEST(test_score_calculation_all_types);

  // Helper function tests
  RUN_TEST(test_level_to_string_no_password);
  RUN_TEST(test_level_to_string_very_weak);
  RUN_TEST(test_level_to_string_weak);
  RUN_TEST(test_level_to_string_medium);
  RUN_TEST(test_level_to_string_strong);
  RUN_TEST(test_level_to_string_very_strong);

  // Edge case tests
  RUN_TEST(test_whitespace_in_password);
  RUN_TEST(test_special_characters_variety);
  RUN_TEST(test_very_long_password);
  RUN_TEST(test_numbers_at_end);
  RUN_TEST(test_special_chars_at_start);

  // Real-world tests
  RUN_TEST(test_common_weak_password_password);
  RUN_TEST(test_common_weak_password_123456);
  RUN_TEST(test_common_weak_password_qwerty);
  RUN_TEST(test_common_weak_password_abc123);
  RUN_TEST(test_strong_password_example1);
  RUN_TEST(test_strong_password_example2);
  RUN_TEST(test_strong_password_example3);

  // Boundary tests
  RUN_TEST(test_exactly_8_characters);
  RUN_TEST(test_exactly_12_characters);
  RUN_TEST(test_exactly_16_characters);
  RUN_TEST(test_single_character);

  return UNITY_END();
}
