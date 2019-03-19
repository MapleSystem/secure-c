//bats @test "nested_if.c: Check pointers in nested if-statements" {
//bats   run secure-c nested_if.c --
//bats   [ $status = 0 ]
//bats }

int bar(int* _Nullable p, int* _Nullable q) {
  if (p != 0) {
    if (q != 0) {
		*p = *q;
		return 0;
	}
	*p = 1;
  }
  return 0;
}
