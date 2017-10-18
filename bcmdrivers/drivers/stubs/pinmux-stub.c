/**
 * Stub file to satisify USB driver for functions orginally in shared/drivers/pinmux
 */

#include <bcm_map_part.h>

void bcm_set_pinmux(unsigned int pin_num, unsigned int mux_num)
{
    unsigned int tp_blk_data_lsb;
    // printk("set pinmux %d to %d\n",pin_num, mux_num);
    tp_blk_data_lsb= 0;
    tp_blk_data_lsb |= pin_num;
    tp_blk_data_lsb |= (mux_num << PINMUX_DATA_SHIFT);
    GPIO->TestPortBlockDataMSB = 0;
    GPIO->TestPortBlockDataLSB = tp_blk_data_lsb;
    GPIO->TestPortCmd = LOAD_MUX_REG_CMD;
}
