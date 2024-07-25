#include "core.h"
#include "stdio.h"

double dynarun_time = 0.0;
double global_fillblock64_time = 0.0;

int main(int argc, const char **argv, char **env) {

    x64emu_t* emu = NULL;

    elfheader_t* elf_header = NULL;
    if (initialize(argc, argv, env, &emu, &elf_header, 1)) {
        return -1;
    }
    int emulate_ret = emulate(emu,elf_header);

    printf("Runblock: %f microseconds\n",dynarun_time);
    printf("Fillblock: %f microseconds\n",global_fillblock64_time);
    printf("Fillblock/Runblock = %f%\n",global_fillblock64_time/dynarun_time *100);
    
    return emulate_ret;
}
