#ifndef DETECT_UTIL_H
#define DETECT_UTIL_H

#ifndef mdebug1
#define mdebug1(...) fprintf(stdout, __VA_ARGS__)
#endif /* mdebug1 */
#ifndef merror
#define merror(...) fprintf(stderr, __VA_ARGS__)
#endif /* merror */

// print debug
#define PRINT_DEBUG(...) fprintf(stdout, __VA_ARGS__, __FILE__, __LINE__)
// print to stderr macro
#define PRINT_ERR(...) fprintf(stderr, __VA_ARGS__, __FILE__, __LINE__)

#endif /* DETECT_UTIL_H */