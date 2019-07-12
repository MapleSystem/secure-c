// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
int bar(int *p, int *q) {
  if (p != 0) {
    if (q != 0) {
		*p = *q;
		return 0;
	}
	*p = 1;
  }
  return 0;
}
