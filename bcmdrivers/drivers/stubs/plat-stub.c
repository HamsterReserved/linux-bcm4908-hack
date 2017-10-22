/**
 * Stub file to satisify PCI-E driver for functions orginally in plat-bcm
 */

#include <linux/mm.h>
#include <linux/sysinfo.h>

unsigned long getMemorySize(void)
{
    struct sysinfo i;
    static unsigned long memsize = -1;

    if (memsize <0 ) {
        si_meminfo(&i);
        memsize = i.totalram;
    }

    return memsize;
}
