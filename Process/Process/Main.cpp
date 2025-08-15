#include <Windows.h>
#include <cstdio>

void test(int* number)
{
	for (;;)
	{
		printf("Value at the pointer [%p] is -> [%d] \n", number, *number);
		Sleep(450);
		system("CLS");
	}
}

void init(int* addr)
{
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)test, addr, 0, 0);
}

int main()
{
	int size = 0;
	
	printf("Size to allocate -> ");
	scanf_s("%d", &size);

	int* addr = (int*)malloc(size);
	printf("Allocated [%d] bytes at [%p]\n", size, addr);

	printf("Value to give the pointer at [%p] -> ", addr);
	scanf_s("%d", addr);
	
	init(addr);

a:
	
	goto a;

}
