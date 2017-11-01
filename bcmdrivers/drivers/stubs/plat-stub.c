/**
 * Stub file to satisify PCI-E driver for functions orginally in plat-bcm
 */

#include <linux/mm.h>

unsigned long getMemorySize(void)
{
    static unsigned long memsize = ~0;

    if (memsize == ~0) {
        memsize = get_num_physpages() << PAGE_SHIFT;
    }

    return memsize;
}
