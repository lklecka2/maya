#include <stdio.h>
__attribute__((noinline)) int cfg_compute(int value, int rounds) {
    int acc=value;
    for(int i=0;i<rounds;i++) {
        if((i&1)==0) acc=acc*3+1;
        else acc-=i;
    }
    if(acc<0) return -acc;
    return acc+5;
}
int main(void){int v=cfg_compute(2,6);printf("cfg=%d\n",v);return v==49?0:1;}
