/**
 * Stub file to satisify PCI-E driver for functions orginally in drivers/char/board
 */

#include <linux/string.h>

#include <bcm_map_part.h>

int kerSysGetPciePortEnable(int port)
{
    int ret = 1;
#if defined (CONFIG_BCM96838)
    unsigned int chipId = (PERF->RevID & CHIP_ID_MASK) >> CHIP_ID_SHIFT;

    switch (chipId)
    {
        case 1:        // 68380
        case 6:        // 68380M
        case 7:        // 68389
            ret = 1;
            break;
            
        case 3:        // 68380F
            if(port == 0)
                ret = 1;
            else
                ret = 0;
            break;
        
        case 4:        // 68385
        case 5:        // 68381
        default:
            ret = 0;
            break;
    }
#elif defined (CONFIG_BCM96848)
    unsigned int chipId = (PERF->RevID & CHIP_ID_MASK) >> CHIP_ID_SHIFT;

    switch (chipId)
    {
        case 0x050d:    // 68480F
        case 0x051a:    // 68481P
        case 0x05c0:    // 68486
        case 0x05bd:    // 68485W
        case 0x05be:    // 68488
            ret = 1;
            break;
        default:
            ret = 0;    // 68485, 68481
            break;
    }

    if (port != 0)
        ret = 0;
#elif defined (CONFIG_BCM96858)
    unsigned int chipId;
    bcm_otp_get_chipid(&chipId);

    switch (chipId)
    {
        case 0:
        case 1:     // 68580X
            if ((port == 0) || (port == 1) || ((port == 2) && (MISC->miscStrapBus & MISC_STRAP_BUS_PCIE_SATA_MASK)))
                ret = 1;
            else            
                ret = 0;
            break;
        case 3:     // 68580H
            if ((port == 0) || (port == 1))
                ret = 1;
            else
                ret = 0;
            break;
        case 2:     // 55040
            if (port == 0)
                ret = 1;
            else
                ret = 0;
            break;
        case 4:     // 55040P
                ret = 0;
            break;
        default:
            ret = 0;
            break;
    }
#endif	
    return ret;
}

/***************************************************************************
 * Function Name: kerSysGetChipId
 * Description  : Map id read from device hardware to id of chip family
 *                consistent with  BRCM_CHIP
 * Returns      : chip id of chip family
 ***************************************************************************/
int kerSysGetChipId(void) { 
        int r;
#if   defined(CONFIG_BCM96838)
        r = 0x6838;
#elif defined(CONFIG_BCM96848)
        r = 0x6848;
#elif defined(CONFIG_BCM96858)
        r = 0x6858;
#elif defined(CONFIG_BCM960333)
        r = 0x60333;
#elif defined(CONFIG_BCM947189)
        r = 0x47189;
#else
        r = (int) ((PERF->RevID & CHIP_ID_MASK) >> CHIP_ID_SHIFT);
        /* Force BCM63168, BCM63169, and BCM63269 to be BCM63268) */
        if( ( (r & 0xffffe) == 0x63168 )
          || ( (r & 0xffffe) == 0x63268 ))
            r = 0x63268;

        /* Force 6319 to be BCM6318 */
        if (r == 0x6319)
            r = 0x6318;

#endif

        return(r);
}

int kerSysGetSdramSize( void )
{
    unsigned long getMemorySize(void); /* Does not have a header */
    return getMemorySize();
}

int kerSysGetMacAddress(unsigned char *pucaMacAddr, unsigned long ulId)
{
    static unsigned char macaddr[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(pucaMacAddr, macaddr, sizeof(macaddr));
    return 0;
}

int kerSysReleaseMacAddress(unsigned char *pucaMacAddr)
{
    return 0;
}