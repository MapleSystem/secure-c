// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <secure_c.h>

typedef struct {
	int *p;
} myStruct;

void bar(myStruct ms) __attribute__((secure_c_in(ms.p, nonnull)));

void foo() {
  myStruct ms1 = {NULL};

  bar(ms1); // expected-warning {{callee's in-constraint is not satisfied}}

  if (ms1.p)
    bar(ms1);
}
