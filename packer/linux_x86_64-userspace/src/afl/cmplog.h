#pragma once 

void nyx_init_cmplog_start(void);
void run_cmplog_executable(void* input, size_t size, uint32_t worker_id);
void export_cmplog_map(void);
void init_aflpp_cmplog(void);