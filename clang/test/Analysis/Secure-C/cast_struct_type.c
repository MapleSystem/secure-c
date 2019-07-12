// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// This test is expected to fail until #185 is implemented
// XFAIL: *
#include <stddef.h>
#include <secure_c.h>

struct NullableStruct {
  int *p;
};

struct NonnullStruct {
  int *p __attribute__((nonnull));
};

int read_struct(struct NullableStruct *p) __attribute__((secure_c_in(p, nonnull))) {
  struct NonnullStruct *q = (struct NonnullStruct *)p;
  return *q->p;
}
