#include <stdint.h>
#include "misc/syscalls.h"
#include "nyx.h"

__attribute__((weak)) extern uint32_t __afl_dictionary_len;
uint32_t* __afl_dictionary_len_ptr = &__afl_dictionary_len;

__attribute__((weak)) extern uint8_t* __afl_dictionary;
uint8_t** __afl_dictionary_ptr = &__afl_dictionary;

void check_afl_auto_dict(){
    /* copy AFL autodict over to host */
    if (__afl_dictionary_len_ptr && __afl_dictionary_ptr){
        if (__afl_dictionary_len && __afl_dictionary){
            _mlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
            kafl_dump_file_t file_obj = {0};
            file_obj.file_name_str_ptr = (uintptr_t)"afl_autodict.txt";
            file_obj.append = 1;
            file_obj.bytes = __afl_dictionary_len;
            file_obj.data_ptr = (uintptr_t)__afl_dictionary;
            kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
            _munlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
        }
    }
}
