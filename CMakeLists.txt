cmake_minimum_required(VERSION 3.15)
project(password_checker LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# warnings
add_compile_options(-Wall -Wextra)

# include headers
include_directories(include)

# build library
add_library(pwcheck_lib STATIC
    src/analyzer.c
    src/generator.c
    src/validator.c
    src/ui.c
)

target_link_libraries(pwcheck_lib PRIVATE m)

# build main program
add_executable(password_checker src/main.c)
target_link_libraries(password_checker PRIVATE pwcheck_lib)

# build tests
add_executable(test_analyzer tests/test_analyzer.c)
target_link_libraries(test_analyzer PRIVATE pwcheck_lib)

add_executable(test_generator tests/test_generator.c)
target_link_libraries(test_generator PRIVATE pwcheck_lib)