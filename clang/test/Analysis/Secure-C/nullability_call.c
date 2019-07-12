// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <secure_c.h>
#include <stddef.h>

void foo_nullable(int *a);
void foo_nonnull(int *a) __attribute__((secure_c_in(a, nonnull)));

void call(int *a, int *b) __attribute__((secure_c_in(b, nonnull))) {
  foo_nullable(a);
  foo_nonnull(a); // expected-warning {{in-constraint is not satisfied}}
  if (a)
    foo_nonnull(a);

  foo_nullable(b);
  foo_nonnull(b);

  int x;
  foo_nullable(&x);
  foo_nonnull(&x);

  int *c = a;
  foo_nullable(c);
  foo_nonnull(c); // expected-warning {{in-constraint is not satisfied}}

  int *d = b;
  foo_nullable(d);
  foo_nonnull(d);

  int *e = &x;
  foo_nullable(e);
  foo_nonnull(e);
}
