// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <stddef.h>
#include <stdio.h>

void foo() {
	char * data;
	data = NULL;
	printf("%c", data[0]); // expected-warning {{illegal access of nullable pointer}}
}
