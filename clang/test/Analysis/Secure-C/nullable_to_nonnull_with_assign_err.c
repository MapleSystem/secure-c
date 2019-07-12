// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <stddef.h>
#include <stdio.h>

void bar(int i) {
	int * p;
	int n;

	if (i > 0) {
		p = &n;
    printf("%d", *p);
	} else {
		p = NULL;
		// expected-warning@+1 {{illegal access of nullable pointer}}
    printf("%d", *p);
	}

	// expected-warning@+1 {{illegal access of nullable pointer}}
	printf("%d", *p);
}
