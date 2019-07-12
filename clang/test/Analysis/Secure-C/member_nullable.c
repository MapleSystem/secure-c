// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
typedef struct {
  int count;
  int val;
} foo;

int get_count(foo *f) {
  return f->count; // expected-warning {{illegal access of nullable pointer}}
}
