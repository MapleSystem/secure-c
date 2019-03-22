//bats @test "nullable_to_nonnull_with_assign_err.c: make a pointer nonnull through assignment" {
//bats   run secure-c nullable_to_nonnull_with_assign_err.c --
//bats   [ $status = 1 ] && echo ${lines[2]}
//bats   [[ ${lines[0]} =~ ":19:22: error: illegal access of nullable pointer type 'int *'" ]]
//bats   [[ ${lines[3]} =~ ":21:15: error: illegal access of nullable pointer type 'int *'" ]]
//bats }

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
        printf("%d", *p);
	}
	printf("%d", *p);
}
