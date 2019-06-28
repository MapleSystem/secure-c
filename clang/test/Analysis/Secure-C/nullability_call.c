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

typedef struct foo {
  int *count;
  struct foo *ptr;
} foo;

void nonnull_field(foo *f)
    __attribute__((secure_c_in(f, nonnull), secure_c_in(f->count, nonnull)));

void call_nonnull_field(foo *f, foo *g, foo *h)
    __attribute__((secure_c_in(g, nonnull), secure_c_in(h, nonnull),
                   secure_c_in(h->count, nonnull))) {
  nonnull_field(f); // expected-warning {{in-constraint is not satisfied}}
  nonnull_field(g); // expected-warning {{in-constraint is not satisfied}}
  nonnull_field(h);

  if (f) {
    nonnull_field(f); // expected-warning {{in-constraint is not satisfied}}
    if (f->count)
      nonnull_field(f);
  }

  if (g->count) {
    nonnull_field(g);
  }
}
