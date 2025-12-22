#include "clovo/analyzer.h"
#include "clovo/generator.h"
#include "clovo/ui.h"
#include "clovo/policy.h"
#include "clovo/comparison.h"
#include "clovo/export.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PASSWORD_LENGTH 256
#define DEFAULT_GENERATE_LENGTH 16
#define MAX_BATCH_SIZE 1000

void print_usage(const char *program_name) {
  static int use_colors = -1;
  if (use_colors == -1) {
    const char *term = getenv("TERM");
    use_colors = (term && isatty(STDOUT_FILENO) && 
                  (strstr(term, "xterm") || strstr(term, "color") || 
                   strstr(term, "256") || strstr(term, "ansi")));
  }
  
  const char *reset = use_colors ? RESET : "";
  const char *bold = use_colors ? BOLD : "";
  const char *cyan = use_colors ? CYAN : "";
  const char *dim = use_colors ? DIM : "";
  
  printf("\n");
  if (use_colors) {
    printf("%s╔══════════════════════════════════════════════════════════╗%s\n", cyan, reset);
    printf("%s║%s  %sClovo - Password Strength Analyzer & Generator%s          %s║%s\n", 
           cyan, reset, bold, reset, cyan, reset);
    printf("%s╚══════════════════════════════════════════════════════════╝%s\n", cyan, reset);
  } else {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  Clovo - Password Strength Analyzer & Generator\n");
    printf("═══════════════════════════════════════════════════════════\n");
  }
  
  printf("\n");
  printf("  %sUsage:%s\n", bold, reset);
  printf("  ──────────────────────────────────────────────────────────\n");
  printf("    %s%s <password>%s                    Analyze password strength\n", 
         cyan, program_name, reset);
  printf("    %s%s --generate [length]%s           Generate password (default: %d)\n", 
         cyan, program_name, reset, DEFAULT_GENERATE_LENGTH);
  printf("    %s%s --passphrase [words]%s         Generate passphrase (default: 4 words)\n", 
         cyan, program_name, reset);
  printf("    %s%s --batch <file>%s                Analyze passwords from file\n", 
         cyan, program_name, reset);
  printf("    %s%s --compare <pw1> <pw2>%s         Compare two passwords\n", 
         cyan, program_name, reset);
  printf("    %s%s --policy <type> <password>%s    Validate against policy (nist/pci/basic)\n", 
         cyan, program_name, reset);
  printf("    %s%s --json <password>%s            Output in JSON format\n", 
         cyan, program_name, reset);
  printf("    %s%s --csv <password>%s              Output in CSV format\n", 
         cyan, program_name, reset);
  printf("    %s%s --export <format> <file>%s      Export results to file (json/csv)\n", 
         cyan, program_name, reset);
  printf("    %s%s --help%s                        Show this help\n", 
         cyan, program_name, reset);
  
  printf("\n");
  printf("  %sExamples:%s\n", bold, reset);
  printf("  ──────────────────────────────────────────────────────────\n");
  printf("    %s%s \"MyP@ssw0rd\"%s\n", dim, program_name, reset);
  printf("    %s%s --generate 24%s\n", dim, program_name, reset);
  printf("    %s%s --passphrase 5%s\n", dim, program_name, reset);
  printf("    %s%s --batch passwords.txt%s\n", dim, program_name, reset);
  printf("    %s%s --compare \"old\" \"new\"%s\n", dim, program_name, reset);
  printf("    %s%s --policy nist \"password\"%s\n", dim, program_name, reset);
  printf("    %s%s --json \"password\"%s\n", dim, program_name, reset);
  
  printf("\n");
}

// process batch file
int process_batch(const char *filename, export_format_t format, const char *output_file) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
    return 1;
  }
  
  char line[512];
  password_strength_t results[MAX_BATCH_SIZE];
  const char *passwords[MAX_BATCH_SIZE];
  char password_storage[MAX_BATCH_SIZE][MAX_PASSWORD_LENGTH + 1];
  int count = 0;
  
  while (fgets(line, sizeof(line), file) && count < MAX_BATCH_SIZE) {
    // remove newline
    line[strcspn(line, "\r\n")] = '\0';
    
    if (strlen(line) == 0) continue;
    if (strlen(line) > MAX_PASSWORD_LENGTH) {
      fprintf(stderr, "Warning: Skipping password longer than %d characters\n", MAX_PASSWORD_LENGTH);
      continue;
    }
    
    strcpy(password_storage[count], line);
    passwords[count] = password_storage[count];
    results[count] = analyze_password(passwords[count]);
    count++;
  }
  
  fclose(file);
  
  if (count == 0) {
    fprintf(stderr, "Error: No passwords found in file\n");
    return 1;
  }
  
  if (output_file) {
    export_batch_results(results, passwords, count, output_file, format);
    printf("Exported %d results to %s\n", count, output_file);
  } else {
    for (int i = 0; i < count; i++) {
      printf("\n--- Password %d ---\n", i + 1);
      if (format == EXPORT_JSON || format == EXPORT_CSV) {
        export_analysis_stdout(&results[i], passwords[i], format);
      } else {
        display_password_analysis(&results[i]);
      }
    }
  }
  
  return 0;
}

int main(int argc, char *argv[]) {
  // initialize generator
  if (init_generator("./data") != GEN_SUCCESS) {
    fprintf(stderr, "Warning: Could not load common passwords list\n");
  }

  // handle no arguments
  if (argc < 2) {
    print_usage(argv[0]);
    cleanup_generator();
    return 1;
  }

  // handle --help
  if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
    print_usage(argv[0]);
    cleanup_generator();
    return 0;
  }

  // handle --generate
  if (strcmp(argv[1], "--generate") == 0 || strcmp(argv[1], "-g") == 0) {
    size_t length = DEFAULT_GENERATE_LENGTH;
    
    if (argc >= 3) {
      char *endptr;
      long parsed_length = strtol(argv[2], &endptr, 10);
      
      if (*endptr != '\0' || parsed_length <= 0) {
        fprintf(stderr, "Error: Invalid length '%s'. Must be a positive integer.\n", argv[2]);
        cleanup_generator();
        return 1;
      }
      
      if (parsed_length > MAX_PASSWORD_LENGTH) {
        fprintf(stderr, "Error: Length must be <= %d\n", MAX_PASSWORD_LENGTH);
        cleanup_generator();
        return 1;
      }
      
      length = (size_t)parsed_length;
    }

    generator_options_t opts;
    init_generator_options(&opts);
    
    char password[MAX_PASSWORD_LENGTH + 1];
    generator_error_t gen_result = generate_password(password, sizeof(password), length, &opts);
    
    if (gen_result != GEN_SUCCESS) {
      fprintf(stderr, "Error generating password: %s\n", generator_error_string(gen_result));
      cleanup_generator();
      return 1;
    }

    password_strength_t analysis = analyze_password(password);
    display_generated_password(password, &analysis);
    
    cleanup_generator();
    return 0;
  }

  // handle --passphrase
  if (strcmp(argv[1], "--passphrase") == 0 || strcmp(argv[1], "-p") == 0) {
    int word_count = 4;
    
    if (argc >= 3) {
      char *endptr;
      long parsed_count = strtol(argv[2], &endptr, 10);
      
      if (*endptr != '\0' || parsed_count < 2 || parsed_count > 10) {
        fprintf(stderr, "Error: Word count must be between 2 and 10\n");
        cleanup_generator();
        return 1;
      }
      
      word_count = (int)parsed_count;
    }

    generator_options_t opts;
    init_generator_options(&opts);
    
    char passphrase[256];
    generator_error_t gen_result = generate_passphrase(passphrase, sizeof(passphrase), word_count, &opts);
    
    if (gen_result != GEN_SUCCESS) {
      fprintf(stderr, "Error generating passphrase: %s\n", generator_error_string(gen_result));
      cleanup_generator();
      return 1;
    }

    password_strength_t analysis = analyze_password(passphrase);
    display_generated_password(passphrase, &analysis);
    
    cleanup_generator();
    return 0;
  }

  // handle --batch
  if (strcmp(argv[1], "--batch") == 0 || strcmp(argv[1], "-b") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Error: --batch requires a filename\n");
      cleanup_generator();
      return 1;
    }
    
    export_format_t format = EXPORT_TEXT;
    const char *output_file = NULL;
    
    // check for format and output options
    for (int i = 3; i < argc; i++) {
      if (strcmp(argv[i], "--json") == 0) {
        format = EXPORT_JSON;
      } else if (strcmp(argv[i], "--csv") == 0) {
        format = EXPORT_CSV;
      } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
        output_file = argv[++i];
      }
    }
    
    int ret = process_batch(argv[2], format, output_file);
    cleanup_generator();
    return ret;
  }

  // handle --compare
  if (strcmp(argv[1], "--compare") == 0 || strcmp(argv[1], "-c") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Error: --compare requires two passwords\n");
      cleanup_generator();
      return 1;
    }
    
    similarity_result_t result = compare_passwords(argv[2], argv[3]);
    
    printf("\nPassword Comparison:\n");
    printf("──────────────────────────────────────────────────────────\n");
    printf("Similarity Score: %.2f%%\n", result.similarity_score * 100);
    printf("Edit Distance: %d\n", result.edit_distance);
    printf("Common Characters: %d\n", result.common_chars);
    printf("Common Positions: %d\n", result.common_positions);
    printf("Too Similar: %s\n", result.is_similar ? "Yes" : "No");
    
    if (result.is_similar) {
      printf("\nWarning: These passwords are too similar!\n");
    }
    
    cleanup_generator();
    return 0;
  }

  // handle --policy
  if (strcmp(argv[1], "--policy") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Error: --policy requires policy type and password\n");
      cleanup_generator();
      return 1;
    }
    
    policy_type_t policy_type = POLICY_CUSTOM;
    if (strcmp(argv[2], "nist") == 0) {
      policy_type = POLICY_NIST;
    } else if (strcmp(argv[2], "pci") == 0 || strcmp(argv[2], "pci-dss") == 0) {
      policy_type = POLICY_PCI_DSS;
    } else if (strcmp(argv[2], "basic") == 0) {
      policy_type = POLICY_BASIC;
    }
    
    password_policy_t policy;
    init_policy(&policy, policy_type);
    
    policy_result_t result = validate_policy(argv[3], &policy);
    
    printf("\nPolicy Validation (%s):\n", policy_type_to_string(policy_type));
    printf("──────────────────────────────────────────────────────────\n");
    printf("Status: %s\n", result.passed ? "PASSED" : "FAILED");
    
    if (!result.passed) {
      printf("\nViolations:\n");
      for (int i = 0; i < result.violations_count; i++) {
        printf("  - %s\n", result.violations[i]);
      }
    }
    
    cleanup_generator();
    return result.passed ? 0 : 1;
  }

  // handle --json
  if (strcmp(argv[1], "--json") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Error: --json requires a password\n");
      cleanup_generator();
      return 1;
    }
    
    password_strength_t result = analyze_password(argv[2]);
    export_analysis_stdout(&result, argv[2], EXPORT_JSON);
    cleanup_generator();
    return 0;
  }

  // handle --csv
  if (strcmp(argv[1], "--csv") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Error: --csv requires a password\n");
      cleanup_generator();
      return 1;
    }
    
    password_strength_t result = analyze_password(argv[2]);
    export_analysis_stdout(&result, argv[2], EXPORT_CSV);
    cleanup_generator();
    return 0;
  }

  // handle --export
  if (strcmp(argv[1], "--export") == 0 || strcmp(argv[1], "-e") == 0) {
    if (argc < 5) {
      fprintf(stderr, "Error: --export requires format, filename, and password\n");
      cleanup_generator();
      return 1;
    }
    
    export_format_t format = EXPORT_JSON;
    if (strcmp(argv[2], "csv") == 0) {
      format = EXPORT_CSV;
    } else if (strcmp(argv[2], "json") == 0) {
      format = EXPORT_JSON;
    }
    
    password_strength_t result = analyze_password(argv[4]);
    int ret = export_analysis(&result, argv[4], argv[3], format);
    
    if (ret == 0) {
      printf("Exported analysis to %s\n", argv[3]);
    } else {
      fprintf(stderr, "Error exporting to file\n");
    }
    
    cleanup_generator();
    return ret;
  }

  // handle password analysis (default case)
  if (argc == 2) {
    const char *password = argv[1];
    
    if (strlen(password) > MAX_PASSWORD_LENGTH) {
      fprintf(stderr, "Error: Password too long (max %d characters)\n", MAX_PASSWORD_LENGTH);
      cleanup_generator();
      return 1;
    }

    password_strength_t result = analyze_password(password);
    
    if (result.level == NO_PASSWORD) {
      fprintf(stderr, "Error: No password provided\n");
      cleanup_generator();
      return 1;
    }

    display_password_analysis(&result);
    cleanup_generator();
    return 0;
  }

  // too many arguments
  fprintf(stderr, "Error: Too many arguments\n");
  print_usage(argv[0]);
  cleanup_generator();
  return 1;
}
