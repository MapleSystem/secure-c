//bats @test "field_access.c: access fields of structs not through pointers" {
//bats   run secure-c field_access.c --
//bats   [ $status = 0 ]
//bats }

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