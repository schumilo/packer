#pragma once 

void enable_cmplog_exit_handler(void(*cmplog_handler_fptr)(void));
void nyx_exit();
void nyx_fast_exit(void);