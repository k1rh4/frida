#include<stdio.h>
#include<time.h>

int main( int argc, char* argv[])
{
    int i =0;
    printf("TEST\n");
    for ( i = 0; i < 10; i++)
    {
        sleep(1);
        if(i % 2 ==0) printf("A\n");
        else printf("B\n");
    }


    return 0;
}
