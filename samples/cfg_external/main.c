#include <stdio.h>
#include <string.h>
__attribute__((noinline)) int cfg_external(const char* text){size_t n=strlen(text);return (int)n+3;}
int main(void){int value=cfg_external("boundary");printf("external=%d\n",value);return value==11?0:1;}
