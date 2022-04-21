#define _GNU_SOURCE

#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdlib.h>
#include "misc/exit_handler.h"
#include "misc/harness_state.h"
#include "misc/syscalls.h"
#include "misc/debug.h"
#include "nyx.h"

#define CMPLOG_BUFFER_SIZE 0x4080000

extern bool fuzz_process;
static void nyx_cmplog_exit_handler(void);

char* cmplog_file = NULL;

void nyx_init_cmplog_start(void){

    //hprintf("????? %s\n", __func__);

    cmplog_file = real_getenv("CMPLOG_FILE");
    //hprintf("cmplog_file: %s\n", cmplog_file);

    fuzz_process = true;

    enable_cmplog_exit_handler(nyx_cmplog_exit_handler);
    atexit(nyx_fast_exit);

    struct stat st;
    stat("/tmp/cmplog_input", &st);
    int size = st.st_size;

    hprintf("size: %x\n", size);

    int input_file = open("/tmp/cmplog_input", O_RDONLY | O_EXCL, 0644);
    hprintf("input_file: %d\n", input_file);

#ifndef LEGACY_MODE      
    void* payload_buffer = mmap(NULL, size, PROT_READ, MAP_PRIVATE, input_file, 0);
#else
    kAFL_payload* payload_buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, input_file, 0);
#endif

    //hprintf("error? -> %s\n", strerror(errno));

    hprintf("payload_buffer -> %p\n", payload_buffer);

    hprintf_hexdump(payload_buffer, 32);

    bool stdin_mode = !get_harness_state()->legacy_file_mode;

    hprintf("stdin_mode -> %d\n", stdin_mode);

    if(stdin_mode){
            struct iovec iov;

            int pipefd[2];
            int ret = pipe(pipefd);
    
            if(size){
                iov.iov_base = payload_buffer;
                iov.iov_len = size;
                ret = vmsplice(pipefd[1], &iov, 1, SPLICE_F_GIFT);
            }
            real_dup2(pipefd[0],STDIN_FILENO);
            close(pipefd[1]);
    }
    else{
        habort("argv (not implemented)\n");
        /*
        if(unlikely(write(fd, payload_buffer->data, payload_buffer->size) == -1)){
            habort("Cannot write Nyx input to guest file -> write() failed!\n");
        }
        */
    }

    //habort("Whoops?!\n");
}

void run_cmplog_executable(void* input, size_t size, uint32_t worker_id){

    /* todo: close alls nyx-net fds */

    int pid = syscall(SYS_fork);
            
    if(!pid){

        char* cmplog_env = NULL;
        if(asprintf(&cmplog_env, "CMPLOG_FILE=cmplog_%d", worker_id) == -1){
            habort("???\n");
        }


        /* export file */
        int fd = open("/tmp/cmplog_input", O_WRONLY | O_CREAT, 0644);
        hprintf("write -> %d\n", write(fd, input, size));
        close(fd);

        hprintf("REDQUEEN\n");
        char* args[] = {NULL, "-c", "/tmp/run_cmplog.sh", NULL};
        char* envp[] = {cmplog_env, NULL};
        //int payload_file = open("/bin/sh", O_RDONLY);
        //hprintf("payload_file: %d\n", payload_file);
        execve("/tmp/run_cmplog.sh", args, envp);
        //fexecve(payload_file, args, envp);
        hprintf("ERROR: %s\n", strerror(errno));
        habort("Error: fexecve() has failed (cmplog)...");
    }
    else if(pid > 0){
        while(1){
            sleep(1);
        }
    }
    else{
        habort("Error: fork() has failed (cmplog)...");
    }
}

//#ifdef NYX_CMPLOG

uint8_t* cmplog_map = NULL;

static void nyx_cmplog_exit_handler(void){
    hprintf("%s ---> \n", __func__);
    static kafl_dump_file_t file_obj = {0};

    file_obj.file_name_str_ptr = (uint64_t)cmplog_file;
    file_obj.append = 0;
    file_obj.bytes = 0;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t) (&file_obj));

    file_obj.append = 1;
    file_obj.bytes = CMPLOG_BUFFER_SIZE;
    file_obj.data_ptr = (uint64_t)cmplog_map;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t) (&file_obj));
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    habort("HYPERCALL_KAFL_RELEASE failed (cmplog)?!\n");
}

void init_aflpp_cmplog(void){

    int shm_fd = shmget(IPC_PRIVATE, CMPLOG_BUFFER_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_fd == -1) {
        habort("init_aflpp_cmplog: shmget() failed");
    }

    char* tmp = NULL;

    asprintf(&tmp, "%d", shm_fd);

    hprintf("%s setting --> <%s>\n", __func__, tmp);

    setenv("__AFL_CMPLOG_SHM_ID", tmp, 1);

    cmplog_map = (uint8_t*)shmat(shm_fd, NULL, 0);

    /* touch the memory to assure it`s mapped in the guest's physical memory */
    memset(cmplog_map, 0, CMPLOG_BUFFER_SIZE);

    hprintf_hexdump(cmplog_map, 16);
}

//#endif