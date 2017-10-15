/**
 * Stub file to satisify PCI-E driver for functions orginally in shared/utils
 */

#include <bcm_map_part.h>

unsigned int UtilGetChipRev(void)
{
    unsigned int revId;
#if defined (CONFIG_BCM96848) || defined(_BCM96848_)
    unsigned int otp_revId = bcm_otp_get_revId();
    if (otp_revId == 0)
        revId = 0xA0;
    else if (otp_revId == 1)
        revId = 0xA1;
    else if (otp_revId == 2)
        revId = 0xB0;

#elif defined(CONFIG_BCM960333) || defined(_BCM960333_)
    revId = (PERF->ChipID & CHIP_VERSION_MASK) >> CHIP_VERSION_SHIFT;
#elif defined(CONFIG_BCM947189) || defined(_BCM947189_)
    revId = (MISC->chipid & CID_REV_MASK) >> CID_REV_SHIFT;
#else
    revId = PERF->RevID & REV_ID_MASK;
#endif

    return  revId;
}

