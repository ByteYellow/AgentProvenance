#include <cpuid.h>
#include <stdio.h>
static void leaf(unsigned int f, unsigned int s) {
 unsigned int a,b,c,d;
 __cpuid_count(f,s,a,b,c,d);
 printf("leaf=%08x subleaf=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",f,s,a,b,c,d);
}
int main(void) {
 leaf(0,0);leaf(1,0);leaf(7,0);
 for(unsigned int i=0;i<=12;i++)leaf(13,i);
 return 0;
}
