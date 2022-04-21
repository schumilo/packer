#pragma once 

//#define NYX_DEBUG_AGENT

#ifdef NYX_DEBUG_AGENT
#define HYPERCALL_KAFL_RELEASE_DEBUG
#endif

void hprintf_hexdump(const void* data, size_t size);