//bats @test "nullable_to_nonnull_with_assign.c: make a pointer nonnull through assignment" {
//bats   run secure-c nullable_to_nonnull_with_assign.c --
//bats   [ $status = 0 ]
//bats }

void foo() {
	int * data;
	int tmp = 5;
	data = &tmp;
	printf("%d", *data);
	
	int ** p2;
	p2 = &data;
	printf("%d", *p2);
}