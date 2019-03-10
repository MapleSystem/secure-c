//bats @test "array_indexing.c: use nonnull pointer for array indexing" {
//bats   run secure-c -secure-buffer=false array_indexing.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

void foo() {
	char * _Nonnull data = "abcde";
	printf("%c", data[0]);
}
