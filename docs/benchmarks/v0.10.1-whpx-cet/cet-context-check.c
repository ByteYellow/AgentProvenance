#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <sys/syscall.h>
__attribute__((noinline)) int nested(int x) { volatile int v=x; return v+1; }
static inline long arch(unsigned long op,unsigned long arg) {
 long ret; __asm__ volatile("syscall" : "=a"(ret) : "0"(SYS_arch_prctl), "D"(op), "S"(arg) : "rcx","r11","memory"); return ret;
}
int main(int argc,char **argv) {
 int seconds=argc>1?atoi(argv[1]):120;
 if(seconds<1 || seconds>600) return 2;
 cpu_set_t allowed, next;
 if(sched_getaffinity(0,sizeof(allowed),&allowed)) return 3;
 int cpus[CPU_SETSIZE], count=0;
 for(int i=0;i<CPU_SETSIZE;i++) if(CPU_ISSET(i,&allowed)) cpus[count++]=i;
 if(!count) return 3;
 struct timespec start,now,delay={0,1000000};
 clock_gettime(CLOCK_MONOTONIC,&start);
 long enabled=arch(0x5001,1);
 if(enabled) {printf("enable_result=%ld\n",enabled);return 4;}
 unsigned long status=0,rounds=0;int failed=0;
 if(arch(0x5005,(unsigned long)&status) || status!=1) failed=1;
 printf("started: enable=%ld status=%lu cpus=%d\n",enabled,status,count);fflush(stdout);
 while(!failed) {
  if(nested(nested(40))!=42) {failed=2;break;}
  CPU_ZERO(&next);CPU_SET(cpus[rounds%count],&next);
  if(sched_setaffinity(0,sizeof(next),&next)) {failed=3;break;}
  sched_yield(); nanosleep(&delay,NULL); rounds++;
  clock_gettime(CLOCK_MONOTONIC,&now);
  if(now.tv_sec-start.tv_sec>=seconds) break;
 }
 long disabled=arch(0x5002,1);
 printf("enabled=%ld status=%lu cpus=%d rounds=%lu seconds=%d failed=%d disabled=%ld\n",enabled,status,count,rounds,seconds,failed,disabled);
 return failed || disabled;
}
