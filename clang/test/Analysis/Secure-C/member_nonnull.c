// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <secure_c.h>

typedef struct {
  int count;
  int val;
} foo;

int get_count(foo *f) __attribute__((secure_c_in(f, nonnull))) {
  return f->count;
}
