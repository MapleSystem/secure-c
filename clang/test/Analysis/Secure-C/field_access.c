// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
typedef struct {
	int i;
} myStruct1;

typedef struct {
	int j;
	myStruct1 s;
} myStruct2;

void foo() {
	myStruct2 mystruct;
	mystruct.s.i = 5;
	mystruct.j = 7;
}
