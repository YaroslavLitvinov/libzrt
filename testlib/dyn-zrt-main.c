
#include <stddef.h>

extern int zrt_brk(void *addr);

int main(void)
{
    return zrt_brk(NULL);
}
