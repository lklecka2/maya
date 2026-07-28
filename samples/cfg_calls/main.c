#include <stdio.h>
__attribute__((noinline)) int cfg_add(int a,int b){return a+b;}
__attribute__((noinline)) int cfg_chain(int value){int first=cfg_add(value,3);return cfg_add(first,4)*2;}
__attribute__((noinline)) int cfg_recursive(int n){if(n<=1)return 1;return n*cfg_recursive(n-1);}
__attribute__((noinline)) int cfg_add_one(int n){return n+1;}
__attribute__((noinline,optimize("O2"))) int cfg_tail(int n){return cfg_add_one(n);}
int main(void){int a=cfg_chain(5),b=cfg_recursive(6),c=cfg_tail(9);printf("calls=%d recursion=%d tail=%d\n",a,b,c);return a==24&&b==720&&c==10?0:1;}
