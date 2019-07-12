// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
int bar(int *p, int *q) {
  if (p != 0) {
    if (q != 0) {
		return 0;
	}
	*p = *q; // expected-warning {{illegal access of nullable pointer}}
  }
  return 0;
}
