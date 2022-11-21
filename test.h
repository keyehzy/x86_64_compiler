#ifndef TEST_H
#define TEST_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
     const char* description;
     bool value;
} test;

typedef struct {
     unsigned int len;
     unsigned int cap;
     test *tests;
} test_array;

static inline void ta_push(test_array *ta, test i)
{
     if (ta->len == ta->cap - 1) {
          ta->cap *= 2;
          ta->tests = (test *) realloc(ta->tests, ta->cap * sizeof(test));
     }
     ta->tests[ta->len++] = i;
}

static inline test ta_at(test_array ia, unsigned int n)
{
     return ia.tests[n];
}

static inline test_array ta_init()
{
     test_array ta;
     ta.len = 0;
     ta.cap = 64;
     ta.tests = (test *) malloc(ta.cap * sizeof(test));
     return ta;
}

#define ASSERT(cond) t.value = cond;
#define ASSERT_TRUE(cond) ASSERT(cond)
#define ASSERT_FALSE(cond) ASSERT(!cond)
#define ASSERT_EQ(x, y) ASSERT(x == y)
#define ASSERT_NEQ(x, y) ASSERT(x != y)

#define it(desc, ...)                           \
     {                                          \
          test t = { desc, true };              \
          do {  __VA_ARGS__; } while (0);       \
          ta_push(&suite, t);                   \
     }

static void verify(test_array suite)
{
     unsigned int succeed = 0;
     unsigned int failed = 0;
     unsigned int i = 0;
     for (i = 0; i < suite.len; i++) {
          if (ta_at(suite, i).value == false) {
               failed++;
               printf("%s: ERROR\n", ta_at(suite, i).description);
          }
          else {
               succeed++;
               printf("%s: OK\n", ta_at(suite, i).description);
          }
     }
     printf("\n%d tests run, %d succeeded and %d failed\n", i, succeed, failed);
}

#endif
