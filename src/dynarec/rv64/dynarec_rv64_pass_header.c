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
        dyn->block += 4; dyn->native_size += 4;         \
	dyn->insts[ninst].size2 +=4; \
}while(0)

void pass_header(dynarec_rv64_t* dyn, uintptr_t addr) {
    
    int ninst =0;
    uintptr_t increment_address = (uintptr_t)increment_block_count;
    //printf("increment_address: %p, %b \n",increment_address,increment_address);
    //uintptr_t pc = (uintptr_t)(dyn->block); // 假设当前PC是当前block的地址 + 4
    //printf("pc: %p, %b \n",pc,pc);
    //uintptr_t diff = increment_address - pc;
    // 计算从当前PC到increment_block_count的相对地址
    // printf("diff: %p, %b \n",diff,diff);
    
    uintptr_t upper_offset = SPLIT20(increment_address);
    //printf("upper_address: %p, %b \n",upper_offset,upper_offset);
    uintptr_t lower_offset = SPLIT12(increment_address);
    //printf("lower_address: %p, %b \n",lower_offset,lower_offset);   
    
    ADDI(xSP,xSP,-(8*9));
    SD(xRA,xSP,0);
    SD(A0,xSP,8);
    SD(A1,xSP,16);
    SD(A2,xSP,24);
    SD(A3,xSP,32);
    SD(A4,xSP,40);
    SD(A5,xSP,48);
    SD(A6,xSP,56);
    SD(A7,xSP,64);

    MV(A0,A1);
    LUI(x5, upper_offset);
    ADDI(x5, x5, lower_offset);
    JALR(x5);

    LD(xRA,xSP,0);
    LD(A0,xSP,8);
    LD(A1,xSP,16);
    LD(A2,xSP,24);
    LD(A3,xSP,32);
    LD(A4,xSP,40);
    LD(A5,xSP,48);
    LD(A6,xSP,56);
    LD(A7,xSP,64);

    ADDI(xSP,xSP,(8*9));
}




