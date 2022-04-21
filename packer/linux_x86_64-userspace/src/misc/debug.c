#include <stddef.h>
#include "misc/debug.h"
#include "nyx.h"

#ifdef NYX_DEBUG_AGENT

void hprintf_hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		hprintf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			hprintf(" ");
			if ((i+1) % 16 == 0) {
				hprintf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					hprintf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					hprintf("   ");
				}
				hprintf("|  %s \n", ascii);
			}
		}
	}
}


#else

void hprintf_hexdump(const void* data, size_t size) {
}

#endif
