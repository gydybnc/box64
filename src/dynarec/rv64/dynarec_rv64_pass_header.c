#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include <stdint.h>
#include "block_counter.h"
#include "rv64_emitter.h"

#include "debug.h"
#include "box64context.h"
#include "dynarec.h"
#include "emu/x64emu_private.h"
#include "emu/x64run_private.h"
#include "x64run.h"
#include "x64emu.h"
#include "box64stack.h"
#include "callback.h"
#include "bridge.h"
#include "emu/x64run_private.h"
#include "x64trace.h"
#include "dynarec_native.h"
#include "custommem.h"

#include "rv64_printer.h"
#include "dynarec_rv64_private.h"
#include "dynarec_rv64_functions.h"
#include "dynarec_rv64_helper.h"

#define EMIT(A)     \
do {                                                \
        if(box64_dynarec_dump) print_opcode(dyn, ninst, (uint32_t)A); \
        *(uint32_t*)(dyn->block) = (uint32_t)(A);       \
        dyn->block += 4;         \
}while(0)

void pass_header(dynarec_rv64_t* dyn, uintptr_t addr) {
    
    int ninst =0;
    uintptr_t increment_address = (uintptr_t)increment_block_count;
    printf("increment_address: %p, %b \n",increment_address,increment_address);
    uintptr_t pc = (uintptr_t)(dyn->block + 8); // 假设当前PC是当前block的地址 + 4
    uintptr_t diff = increment_address - pc;
    // 计算从当前PC到increment_block_count的相对地址
     printf("diff: %p, %b \n",diff,diff);
    
    uint32_t upper_offset = SPLIT20(diff);
    printf("upper_address: %p, %b \n",upper_offset,upper_offset);
    uint32_t lower_offset = SPLIT12(diff);
    printf("lower_address: %p, %b \n",lower_offset,lower_offset);   
    AUIPC(x5, SPLIT20(diff));  // 使用 t0 寄存器保存中间地址
    LD(x5, x5, SPLIT12(diff)); // 使用 x0 (zero register) 作为返回地址寄存器，即不保存返回地址
    JALR(x5);
}




