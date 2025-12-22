#ifndef EXPORT_H
#define EXPORT_H

#include "clovo/analyzer.h"
#include <stdio.h>

// export formats
typedef enum { EXPORT_TEXT, EXPORT_JSON, EXPORT_CSV } export_format_t;

// export password analysis to file
int export_analysis(const password_strength_t *result, const char *password,
                    const char *filename, export_format_t format);

// export password analysis to stdout
int export_analysis_stdout(const password_strength_t *result,
                           const char *password, export_format_t format);

// export batch results
int export_batch_results(const password_strength_t *results,
                         const char **passwords, int count,
                         const char *filename, export_format_t format);

#endif
