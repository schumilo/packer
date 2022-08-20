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

    cmplog_file = real_getenv("CMPLOG_FILE");
    if (cmplog_file == NULL){
        habort("Cannot retrieve cmplog_file filename -> CMPLOG_FILE is not set (CMPLOG)!\n");
    }

    fuzz_process = true;
    enable_cmplog_exit_handler(nyx_cmplog_exit_handler);
    atexit(nyx_fast_exit);

    struct stat st;
    stat("/tmp/cmplog_input", &st);
    int size = st.st_size;

    //hprintf("size: %x\n", size);
    int input_file = open("/tmp/cmplog_input", O_RDONLY | O_EXCL, 0644);
    if(input_file == -1){
        habort("Cannot open cmplog file -> open() failed (CMPLOG)!\n");
    }

#ifndef LEGACY_MODE      
    void* payload_buffer = mmap(NULL, size, PROT_READ, MAP_PRIVATE, input_file, 0);
#else
    kAFL_payload* payload_buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, input_file, 0);
#endif


    bool stdin_mode = !get_harness_state()->legacy_file_mode;

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

        char* filename = real_getenv("NYX_LEGACY_FILE_MODE");
        if (filename == NULL){
            habort("Cannot retrieve guest input filename -> NYX_LEGACY_FILE_MODE is not set (CMPLOG)!\n");
        }

        int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, O_RDWR);
        if(fd == -1){
            habort("Cannot open guest input file -> open() failed (CMPLOG)!\n");
        }

        if(ftruncate(fd, 0) != 0){
            habort("Cannot resize guest input file -> ftruncate() failed (CMPLOG)!\n");
        }

        if(write(fd, payload_buffer, size) == -1){
            habort("Cannot write Nyx input to guest file -> write() failed (CMPLOG)!\n");
        }

        close(fd);
    }
}

static void close_all_fds(void){
    int fdlimit = (int)sysconf(_SC_OPEN_MAX);
    for (int i = STDERR_FILENO + 1; i < fdlimit; i++){
         close(i);
    }
}

void run_cmplog_executable(void* input, size_t size, uint32_t worker_id){

    int pid = syscall(SYS_fork);
            
    if(!pid){
        _exit_group(0);
    }
    else if(pid > 0){
        int status;
        _waitpid(pid, NULL, WUNTRACED);

        close_all_fds();

        char* cmplog_env = NULL;
        if(asprintf(&cmplog_env, "CMPLOG_FILE=cmplog_%d", worker_id) == -1){
            habort("???\n");
        }

        /* export file */
        int fd = open("/tmp/cmplog_input", O_WRONLY | O_CREAT, 0644);
        hprintf("write -> %d\n", write(fd, input, size));
        close(fd);

        char* args[] = {NULL, "-c", "/tmp/run_cmplog.sh", NULL};
        char* envp[] = {cmplog_env, NULL};
        //int payload_file = open("/bin/sh", O_RDONLY);
        //hprintf("payload_file: %d\n", payload_file);
        execve("/tmp/run_cmplog.sh", args, envp);
        //fexecve(payload_file, args, envp);
        hprintf("ERROR: %s\n", strerror(errno));
        habort("Error: fexecve() has failed (cmplog)...");
    }
    else{
        habort("Error: fork() has failed (cmplog)...");
    }
}

//#ifdef NYX_CMPLOG

uint8_t* cmplog_map = NULL;

static void nyx_cmplog_exit_handler(void){
    static kafl_dump_file_t file_obj = {0};

    file_obj.file_name_str_ptr = (uint64_t)cmplog_file;
    file_obj.append = 0;
    file_obj.bytes = 0;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t) (&file_obj));

    file_obj.append = 1;
    file_obj.bytes = CMPLOG_BUFFER_SIZE;
    file_obj.data_ptr = (uint64_t)cmplog_map;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t) (&file_obj));

    /* TODO: force snapshot reload at this point */
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

    setenv("__AFL_CMPLOG_SHM_ID", tmp, 1);

    cmplog_map = (uint8_t*)shmat(shm_fd, NULL, 0);

    /* touch the memory to assure it`s mapped in the guest's physical memory */
    memset(cmplog_map, 0, CMPLOG_BUFFER_SIZE);

    //hprintf_hexdump(cmplog_map, 16);
}

//#endif