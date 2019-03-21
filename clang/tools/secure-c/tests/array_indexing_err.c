//bats @test "array_indexing_err.c: use nuallable pointer for array indexing should trigger an error" {
//bats   run secure-c array_indexing_err.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":12:15: error: illegal access of nullable pointer type 'char *'" ]]
//bats }
#include <stddef.h>
#include <stdio.h>

void foo() {
	char * data;
	data = NULL;
	printf("%c", data[0]);
}
