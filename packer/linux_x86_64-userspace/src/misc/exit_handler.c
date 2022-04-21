#include <stdbool.h>
#include "misc/syscalls.h"
#include "misc/debug.h"
#include "nyx.h"

bool cmplog_exit = false;
extern bool fuzz_process;

void(*cmplog_handler)(void) = NULL;

/* 
    Enable this option to boost execution for targets running in reload mode. 
    Breaks non-reload mode.

     ** Experimental stuff as always! **
*/

void enable_cmplog_exit_handler(void(*cmplog_handler_fptr)(void)){
    cmplog_handler = cmplog_handler_fptr;
    cmplog_exit = true;
}

static inline void nyx_exit_noreturn(void){
    if(cmplog_exit){
        cmplog_handler();
    }
    else{
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
        habort("HYPERCALL_KAFL_RELEASE failed?!\n");
    }
}

void nyx_exit(){
#ifdef HYPERCALL_KAFL_RELEASE_DEBUG
    hprintf("HYPERCALL_KAFL_RELEASE in %s %d (%d)\n", __func__, __LINE__, fuzz_process);
#endif
    if(cmplog_exit){
        cmplog_handler();
    }
    else{
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}

void nyx_fast_exit(void){
#ifdef HYPERCALL_KAFL_RELEASE_DEBUG
    hprintf("HYPERCALL_KAFL_RELEASE in %s %d (%d)\n", __func__, __LINE__, fuzz_process);
#endif
    if(fuzz_process){
        nyx_exit_noreturn();
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}

#ifdef NET_FUZZ
void exit(int status){
#ifdef HYPERCALL_KAFL_RELEASE_DEBUG
    hprintf("HYPERCALL_KAFL_RELEASE in %s %d (%d)\n", __func__, __LINE__, fuzz_process);
#endif
    if(fuzz_process){
        nyx_exit_noreturn();
    }

    /* remove the following **two** lines if target runs as daemon (detached from termianl) */
    void (*real_exit)(int) = dlsym(RTLD_NEXT,"exit");
    real_exit(status);
    while(1){}
}
#endif


void pthread_exit(void *retval){
    hprintf("%s: sig:\n", __func__);
    while(1){}
}

int raise(int sig){
    hprintf("%s: sig: %d\n", __func__, sig);
    while(1){}
    nyx_exit_noreturn();
    return 0;
}

int kill(pid_t pid, int sig){
    hprintf("%s: sig: %d [PID:%d]\n", __func__, sig, pid);
    while(1){}
}

#ifdef NET_FUZZ
void _exit(int status){
    if(fuzz_process){
    #ifdef HYPERCALL_KAFL_RELEASE_DEBUG
        hprintf("HYPERCALL_KAFL_RELEASE in %s %d\n", __func__, __LINE__);
    #endif
        nyx_exit_noreturn();
    }
    else{
        real__exit(0);
    }
    while(1){}
}
#endif

pid_t fork(void){
    //hprintf("ATTEMPT TO FORK?!!!\n");
#ifdef LEGACY_MODE
    nyx_exit_noreturn();
#endif
    return _fork();
    while(1){
    }
}

/*
int execve(const char *filename, char *const argv[],
                  char *const envp[]){

#ifdef LEGACY_MODE
    // fix to support bash out-of-the-box 
    nyx_exit_noreturn();
#endif

    hprintf("ATTEMPT TO execve?!!!\n");
    while(1){

    }
}
*/


int execl(const char *pathname, const char *arg, ...){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }
}
       
int execlp(const char *file, const char *arg, ...){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }
}

int execle(const char *pathname, const char *arg, ...){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }    
}
     
#ifdef LEGACY_MODE
int execv(const char *pathname, char *const argv[]){
    //hprintf("ATTEMPT TO %s?!!!\n", __func__);
    nyx_exit_noreturn();
    while(1){
    }     
}
#endif

int execvp(const char *file, char *const argv[]){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }    
}
       
int execvpe(const char *file, char *const argv[],
                       char *const envp[]){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }    
}

int clearenv(void){
    hprintf("ATTEMPT TO clearenv?!!!\n");
    while(1){

    }
}
