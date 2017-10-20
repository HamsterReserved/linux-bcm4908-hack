/**
 * Initialize board profile module.
 */

#include <linux/printk.h>
#include <linux/init.h>
#include <linux/errno.h>

#include <boardparms.h>

#define DEFAULT_BOARD_ID "R8000P"

/* Should have an argument */
static int setupBoardId(void) {
	const char *boardId = DEFAULT_BOARD_ID;
	if (BpSetBoardId(boardId) == BP_SUCCESS) {
		printk("Board profile initialized as %s\n", boardId);
		return 0;
	} else {
		printk("Board profile initialization failed, board ID is %s\n", boardId);
		return -EINVAL;
	}
}

arch_initcall(setupBoardId);
