//bats @test "annotated.c: Leave already annotated types as-is" {
//bats run securify annotated.c --
//bats [ $status = 0 ]
//bats [[ ${lines[@]} -eq 0 ]]
//bats }
#include <stddef.h>

int foo(int * _Nonnull data) {
	return *data;
}

int g;
int bar() {
	int * _Nonnull x = &g;
	return *x;
}

int baz(int * _Nullable x) {
	int * _Nullable b = x;
	if (b != NULL) {
		return *b;
	}
	return 0;
}
