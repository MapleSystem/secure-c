// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>

struct List {
  struct List *next;
  int value;
};

unsigned int List_length(struct List *l) {
  unsigned int length = 0;
  for (; l != NULL; l = l->next, length++); // Safe: null check dominates `l->next`
  return length;
}
