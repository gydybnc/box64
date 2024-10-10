#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include "debug.h"
#include "box64context.h"
#include "dynarec.h"
#include "emu/x64emu_private.h"
#include "emu/x64run_private.h"
#include "x64run.h"
#include "x64emu.h"
#include "box64stack.h"
#include "emu/x64run_private.h"
#include "x64trace.h"
#include "dynablock.h"
#include "dynarec_native.h"
#include "custommem.h"
#include "elfloader.h"

#include "dynarec_arch.h"
#include "dynarec_helper.h"

#ifndef STEP
#error No STEP defined
#endif

#if STEP == 0
#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#endif

#if STEP == 0
typedef struct {
    unsigned char cmp_opcode;
    unsigned char jxx_opcode;
    int identifier;
} CmpJxxPair;

CmpJxxPair cmp_jxx_pairs[] = {
    //Jxx ib: 0x70
    // CMP 0x38: CMP Eb, Gb
    {0x38, 0x74, 0}, // CMP 0x38 后跟 JZ (0x74)
    {0x38, 0x75, 1}, // CMP 0x38 后跟 JNZ (0x75)
    {0x38, 0x7C, 2}, // CMP 0x38 后跟 JL (0x7C)
    {0x38, 0x7D, 3}, // CMP 0x38 后跟 JGE (0x7D)
    {0x38, 0x7E, 4}, // CMP 0x38 后跟 JLE (0x7E)
    {0x38, 0x7F, 5}, // CMP 0x38 后跟 JG (0x7F)
    {0x38, 0x76, 6}, // CMP 0x38 后跟 JBE (0x76)
    {0x38, 0x77, 7}, // CMP 0x38 后跟 JNBE (0x77)

    // CMP 0x39: CMP Ed, Gd
    {0x39, 0x74, 8},
    {0x39, 0x75, 9},
    {0x39, 0x7C, 10},
    {0x39, 0x7D, 11},
    {0x39, 0x7E, 12},
    {0x39, 0x7F, 13},
    {0x39, 0x76, 14},
    {0x39, 0x77, 15},

    // CMP 0x3A: CMP Gb, Eb
    {0x3A, 0x74, 16},
    {0x3A, 0x75, 17},
    {0x3A, 0x7C, 18},
    {0x3A, 0x7D, 19},
    {0x3A, 0x7E, 20},
    {0x3A, 0x7F, 21},
    {0x3A, 0x76, 22},
    {0x3A, 0x77, 23},

    // CMP 0x3B: CMP Gd, Ed
    {0x3B, 0x74, 24},
    {0x3B, 0x75, 25},
    {0x3B, 0x7C, 26},
    {0x3B, 0x7D, 27},
    {0x3B, 0x7E, 28},
    {0x3B, 0x7F, 29},
    {0x3B, 0x76, 30},
    {0x3B, 0x77, 31},

    // CMP 0x3C: CMP AL, Ib
    {0x3C, 0x74, 32},
    {0x3C, 0x75, 33},
    {0x3C, 0x7C, 34},
    {0x3C, 0x7D, 35},
    {0x3C, 0x7E, 36},
    {0x3C, 0x7F, 37},
    {0x3C, 0x76, 38},
    {0x3C, 0x77, 39},


    //Jxx Id: 0x80
    {0x38, 0x84, 40}, // CMP 0x38 后跟 JZ (0x84)
    {0x38, 0x85, 41}, // CMP 0x38 后跟 JNZ (0x85)
    {0x38, 0x8C, 42}, // CMP 0x38 后跟 JL (0x8C)
    {0x38, 0x8D, 43}, // CMP 0x38 后跟 JGE (0x8D)
    {0x38, 0x8E, 44}, // CMP 0x38 后跟 JLE (0x8E)
    {0x38, 0x8F, 45}, // CMP 0x38 后跟 JG (0x8F)
    {0x38, 0x86, 46}, // CMP 0x38 后跟 JBE (0x86)
    {0x38, 0x87, 47}, // CMP 0x38 后跟 JNBE (0x87)

    // CMP 0x39: CMP Ed, Gd
    {0x39, 0x84, 48},
    {0x39, 0x85, 49},
    {0x39, 0x8C, 50},
    {0x39, 0x8D, 51},
    {0x39, 0x8E, 52},
    {0x39, 0x8F, 53},
    {0x39, 0x86, 54},
    {0x39, 0x87, 55},

    // CMP 0x3A: CMP Gb, Eb
    {0x3A, 0x84, 56},
    {0x3A, 0x85, 57},
    {0x3A, 0x8C, 58},
    {0x3A, 0x8D, 59},
    {0x3A, 0x8E, 60},
    {0x3A, 0x8F, 61},
    {0x3A, 0x86, 62},
    {0x3A, 0x87, 63},

    // CMP 0x3B: CMP Gd, Ed
    {0x3B, 0x84, 64},
    {0x3B, 0x85, 65},
    {0x3B, 0x8C, 66},
    {0x3B, 0x8D, 67},
    {0x3B, 0x8E, 68},
    {0x3B, 0x8F, 69},
    {0x3B, 0x86, 70},
    {0x3B, 0x87, 71},

    // CMP 0x3C: CMP AL, Ib
    {0x3C, 0x84, 72},
    {0x3C, 0x85, 73},
    {0x3C, 0x8C, 74},
    {0x3C, 0x8D, 75},
    {0x3C, 0x8E, 76},
    {0x3C, 0x8F, 77},
    {0x3C, 0x86, 78},
    {0x3C, 0x87, 79}
};

#define NUM_PAIRS (sizeof(cmp_jxx_pairs) / sizeof(CmpJxxPair))

int get_pattern_identifier(unsigned char current_opcode, unsigned char next_opcode) {
    for (int i = 0; i < NUM_PAIRS; i++) {
        if (cmp_jxx_pairs[i].cmp_opcode == current_opcode && cmp_jxx_pairs[i].jxx_opcode == next_opcode) {
            return cmp_jxx_pairs[i].identifier;
        }
    }
    return -1; // no found
}
#endif

uintptr_t native_pass(dynarec_native_t* dyn, uintptr_t addr, int alternate, int is32bits)
{
    int ok = 1;
    int ninst = 0;
    int j64;
    uintptr_t ip = addr;
    uintptr_t init_addr = addr;
    rex_t rex;
    int rep = 0;    // 0 none, 1=F2 prefix, 2=F3 prefix
    int need_epilog = 1;
    // Clean up (because there are multiple passes)
    dyn->f.pending = 0;
    dyn->f.dfnone = 0;
    dyn->forward = 0;
    dyn->forward_to = 0;
    dyn->forward_size = 0;
    dyn->forward_ninst = 0;
    dyn->ymm_zero = 0;
    #if STEP == 0
    memset(&dyn->insts[ninst], 0, sizeof(instruction_native_t));
    #endif
    #if STEP == 0
    uint8_t old_opcode;
    uint8_t current_opcode ;
    #endif
    fpu_reset(dyn);
    ARCH_INIT();
    int reset_n = -1; // -1 no reset; -2 reset to 0; else reset to the state of reset_n
    dyn->last_ip = (alternate || (dyn->insts && dyn->insts[0].pred_sz))?0:ip;  // RIP is always set at start of block unless there is a predecessor!
    int stopblock = 2+(FindElfAddress(my_context, addr)?0:1); // if block is in elf_memory, it can be extended with box64_dynarec_bigblock==2, else it needs 3
    // ok, go now
    INIT;
    #if STEP == 0
    uintptr_t cur_page = (addr)&~(box64_pagesize-1);
    #endif
    while(ok) {
        #if STEP == 0
        if(cur_page != ((addr)&~(box64_pagesize-1))) {
            cur_page = (addr)&~(box64_pagesize-1);
            if(!(getProtection(addr)&PROT_READ)) {
                need_epilog = 1;
                break;
            }
        }
        // This test is here to prevent things like TABLE64 to be out of range
        // native_size is not exact at this point, but it should be larger, not smaller, and not by a huge margin anyway
        // so it's good enough to avoid overflow in relative to PC data fectching
        if((dyn->native_size >= MAXBLOCK_SIZE) || (ninst >= MAX_INSTS)) {
            need_epilog = 1;
            break;
        }
        #endif
        fpu_propagate_stack(dyn, ninst);
        ip = addr;
        if (reset_n!=-1) {
            dyn->last_ip = 0;
            if(reset_n==-2) {
                MESSAGE(LOG_DEBUG, "Reset Caches to zero\n");
                dyn->f.dfnone = 0;
                dyn->f.pending = 0;
                fpu_reset(dyn);
                ARCH_RESET();
            } else {
                fpu_reset_cache(dyn, ninst, reset_n);
                dyn->f = dyn->insts[reset_n].f_exit;
                if(dyn->insts[ninst].x64.barrier&BARRIER_FLOAT) {
                    MESSAGE(LOG_DEBUG, "Apply Barrier Float\n");
                    fpu_reset(dyn);
                }
                if(dyn->insts[ninst].x64.barrier&BARRIER_FLAGS) {
                    MESSAGE(LOG_DEBUG, "Apply Barrier Flags\n");
                    dyn->f.dfnone = 0;
                    dyn->f.pending = 0;
                }
            }
            reset_n = -1;
        }
        #if STEP > 0
        else if(ninst && (dyn->insts[ninst].pred_sz>1 || (dyn->insts[ninst].pred_sz==1 && dyn->insts[ninst].pred[0]!=ninst-1)))
            dyn->last_ip = 0;   // reset IP if some jump are coming here
        #endif
        dyn->f.dfnone_here = 0;
        NEW_INST;
        MESSAGE(LOG_DUMP, "New Instruction %s:%p, native:%p\n", is32bits?"x86":"x64",(void*)addr, (void*)dyn->block);
        if(!ninst) {
            GOTEST(x1, x2);
        }
        if(dyn->insts[ninst].pred_sz>1) {SMSTART();}
        if((dyn->insts[ninst].x64.need_before&~X_PEND) && !dyn->insts[ninst].pred_sz) {
            READFLAGS(dyn->insts[ninst].x64.need_before&~X_PEND);
        }
        if(box64_dynarec_test && (!box64_dynarec_test_end || (ip>=box64_dynarec_test_start && ip<box64_dynarec_test_end) )) {
            MESSAGE(LOG_DUMP, "TEST STEP ----\n");
            fpu_reflectcache(dyn, ninst, x1, x2, x3);
            GO_TRACE(x64test_step, 1, x5);
            fpu_unreflectcache(dyn, ninst, x1, x2, x3);
            MESSAGE(LOG_DUMP, "----------\n");
        }
#ifdef HAVE_TRACE
        else if(my_context->dec && box64_dynarec_trace) {
        if((trace_end == 0)
            || ((ip >= trace_start) && (ip < trace_end)))  {
                MESSAGE(LOG_DUMP, "TRACE ----\n");
                fpu_reflectcache(dyn, ninst, x1, x2, x3);
                GO_TRACE(PrintTrace, 1, x5);
                fpu_unreflectcache(dyn, ninst, x1, x2, x3);
                MESSAGE(LOG_DUMP, "----------\n");
            }
        }
#endif	
//////////////////////////////////////////////////////////////////
    #if STEP == 0
        current_opcode = PK(0);
	if(old_opcode){
            int id = get_pattern_identifier(old_opcode, current_opcode);
	    if (id != -1) {
            	//printf("pattern: %p CMP 0x%x | Jxx 0x%x，code: %d\n",(void*)addr, old_opcode, current_opcode, id);
            	dyn->insts[ninst-1].pattern_code = id;
	    	dyn->insts[ninst].pattern_code = id;
	    	//printf("%d %d\n", dyn->insts[ninst].pattern_code,dyn->insts[ninst+1].pattern_code);
	    }
	}   
	old_opcode = current_opcode;
    #endif
////////////////////////////////////////////////////////////////
        rep = 0;
        uint8_t pk = PK(0);
        while((pk==0xF2) || (pk==0xF3) || (pk==0x3E) || (pk==0x26)) {
            switch(pk) {
                case 0xF2: rep = 1; break;
                case 0xF3: rep = 2; break;
                case 0x3E:
                case 0x26: /* ignored */ break;
            }
            ++addr;
            pk = PK(0);
        }
        rex.rex = 0;
        rex.is32bits = is32bits;
        if(!rex.is32bits)
            while(pk>=0x40 && pk<=0x4f) {
                rex.rex = pk;
                ++addr;
                pk = PK(0);
            }

        addr = dynarec64_00(dyn, addr, ip, ninst, rex, rep, &ok, &need_epilog);
        if(dyn->abort)
            return ip;
        INST_EPILOG;
        fpu_reset_scratch(dyn);
        int next = ninst+1;
        #if STEP > 0
        if(dyn->insts[ninst].x64.has_next && dyn->insts[next].x64.barrier) {
            if(dyn->insts[next].x64.barrier&BARRIER_FLOAT) {
                fpu_purgecache(dyn, ninst, 0, x1, x2, x3);
            }
            if(dyn->insts[next].x64.barrier&BARRIER_FLAGS) {
                dyn->f.pending = 0;
                dyn->f.dfnone = 0;
                dyn->last_ip = 0;
            }
        }
        #endif
        #ifndef PROT_READ
        #define PROT_READ 1
        #endif
        #if STEP != 0
        if(!ok && !need_epilog && (addr < (dyn->start+dyn->isize))) {
            ok = 1;
            // we use the 1st predecessor here
            if((ninst+1)<dyn->size && !dyn->insts[ninst+1].x64.alive) {
                // reset fpu value...
                dyn->f.dfnone = 0;
                dyn->f.pending = 0;
                fpu_reset(dyn);
                while((ninst+1)<dyn->size && !dyn->insts[ninst+1].x64.alive) {
                    // may need to skip opcodes to advance
                    ++ninst;
                    NEW_INST;
                    MESSAGE(LOG_DEBUG, "Skipping unused opcode\n");
                    INST_NAME("Skipped opcode");
                    addr += dyn->insts[ninst].x64.size;
                    INST_EPILOG;
                }
            }
            if((dyn->insts[ninst+1].x64.barrier&BARRIER_FULL)==BARRIER_FULL)
                reset_n = -2;    // hack to say Barrier!
            else {
                reset_n = getNominalPred(dyn, ninst+1);  // may get -1 if no predecessor are available
                if(reset_n==-1) {
                    reset_n = -2;
                    if(!dyn->insts[ninst].x64.has_callret) {
                        MESSAGE(LOG_DEBUG, "Warning, Reset Caches mark not found\n");
                    }
                }
            }
        }
        #else
        // check if block need to be stopped, because it's a 00 00 opcode (unreadeable is already checked earlier)
        if((ok>0) && !dyn->forward && !(*(uint8_t*)addr) && !(*(uint8_t*)(addr+1))) {
            if(box64_dynarec_dump) dynarec_log(LOG_NONE, "Stopping block at %p reason: %s\n", (void*)addr, "Next opcode is 00 00");
            ok = 0;
            need_epilog = 1;
        }
        if(dyn->forward) {
            if(dyn->forward_to == addr && !need_epilog && ok>=0) {
                // we made it!
                reset_n = get_first_jump_addr(dyn, addr);
                if(box64_dynarec_dump) dynarec_log(LOG_NONE, "Forward extend block for %d bytes %s%p -> %p (ninst %d - %d)\n", dyn->forward_to-dyn->forward, dyn->insts[dyn->forward_ninst].x64.has_callret?"(opt. call) ":"", (void*)dyn->forward, (void*)dyn->forward_to, reset_n, ninst);
                if(dyn->insts[dyn->forward_ninst].x64.has_callret && !dyn->insts[dyn->forward_ninst].x64.has_next)
                    dyn->insts[dyn->forward_ninst].x64.has_next = 1;  // this block actually continue
                dyn->forward = 0;
                dyn->forward_to = 0;
                dyn->forward_size = 0;
                dyn->forward_ninst = 0;
                ok = 1; // in case it was 0
            } else if ((dyn->forward_to < addr) || ok<=0) {
                // something when wrong! rollback
                if(box64_dynarec_dump) dynarec_log(LOG_NONE, "Could not forward extend block for %d bytes %p -> %p\n", dyn->forward_to-dyn->forward, (void*)dyn->forward, (void*)dyn->forward_to);
                ok = 0;
                dyn->size = dyn->forward_size;
                ninst = dyn->forward_ninst;
                addr = dyn->forward;
                dyn->forward = 0;
                dyn->forward_to = 0;
                dyn->forward_size = 0;
                dyn->forward_ninst = 0;
            }
            // else just continue
        } else if(!ok && !need_epilog && box64_dynarec_bigblock && (getProtection(addr+3)&~PROT_READ))
            if(*(uint32_t*)addr!=0) {   // check if need to continue (but is next 4 bytes are 0, stop)
                uintptr_t next = get_closest_next(dyn, addr);
                if(next && (
                    (((next-addr)<15) && is_nops(dyn, addr, next-addr))
                    /*||(((next-addr)<30) && is_instructions(dyn, addr, next-addr))*/ ))
                {
                    ok = 1;
                    if(dyn->insts[ninst].x64.has_callret && !dyn->insts[ninst].x64.has_next) {
                        dyn->insts[ninst].x64.has_next = 1;  // this block actually continue
                    } else {
                        // need to find back that instruction to copy the caches, as previous version cannot be used anymore
                        // and pred table is not ready yet
                        reset_n = get_first_jump(dyn, next);
                    }
                    if(box64_dynarec_dump) dynarec_log(LOG_NONE, "Extend block %p, %s%p -> %p (ninst=%d, jump from %d)\n", dyn, dyn->insts[ninst].x64.has_callret?"(opt. call) ":"", (void*)addr, (void*)next, ninst+1, dyn->insts[ninst].x64.has_callret?ninst:reset_n);
                } else if(next && (int)(next-addr)<box64_dynarec_forward && (getProtection(next)&PROT_READ)/*box64_dynarec_bigblock>=stopblock*/) {
                    if(!((box64_dynarec_bigblock<stopblock) && !isJumpTableDefault64((void*)next))) {
                        if(dyn->forward) {
                            if(next<dyn->forward_to)
                                dyn->forward_to = next;
                            reset_n = -2;
                            ok = 1;
                        } else {
                            dyn->forward = addr;
                            dyn->forward_to = next;
                            dyn->forward_size = dyn->size;
                            dyn->forward_ninst = ninst;
                            reset_n = -2;
                            ok = 1;
                        }
                    }
                }
            }
        #endif
        if(ok<0)  {
            ok = 0; need_epilog=1;
            #if STEP == 0
            if(ninst) {
                --ninst;
                if(!dyn->insts[ninst].x64.barrier) {
                    BARRIER(BARRIER_FLOAT);
                }
                dyn->insts[ninst].x64.need_after |= X_PEND;
                ++ninst;
            }
            if(dyn->forward) {
                // stopping too soon
                dyn->size = dyn->forward_size;
                ninst = dyn->forward_ninst+1;
                addr = dyn->forward;
                dyn->forward = 0;
                dyn->forward_to = 0;
                dyn->forward_size = 0;
                dyn->forward_ninst = 0;
            }
            #endif
        }
        if((ok>0) && dyn->insts[ninst].x64.has_callret)
            reset_n = -2;
        if((ok>0) && reset_n==-1 && dyn->insts[ninst+1].purge_ymm)
            PURGE_YMM();
        ++ninst;
        #if STEP == 0
        memset(&dyn->insts[ninst], 0, sizeof(instruction_native_t));
        if((ok>0) && (((box64_dynarec_bigblock<stopblock) && !isJumpTableDefault64((void*)addr))
            || (addr>=box64_nodynarec_start && addr<box64_nodynarec_end)))
        #else
        if((ok>0) && (ninst==dyn->size))
        #endif
        {
            #if STEP == 0
            if(dyn->forward) {
                // stopping too soon
                dyn->size = dyn->forward_size;
                ninst = dyn->forward_ninst+1;
                addr = dyn->forward;
                dyn->forward = 0;
                dyn->forward_to = 0;
                dyn->forward_size = 0;
                dyn->forward_ninst = 0;
            }
            #endif
            int j32;
            MAYUSE(j32);
            MESSAGE(LOG_DEBUG, "Stopping block %p (%d / %d)\n",(void*)init_addr, ninst, dyn->size);
            if(!box64_dynarec_dump && addr>=box64_nodynarec_start && addr<box64_nodynarec_end)
                dynarec_log(LOG_INFO, "Stopping block in no-dynarec zone\n");
            --ninst;
            if(!dyn->insts[ninst].x64.barrier) {
                BARRIER(BARRIER_FLOAT);
            }
            #if STEP == 0
            dyn->insts[ninst].x64.need_after |= X_PEND;
            #endif
            ++ninst;
            NOTEST(x3);
            fpu_purgecache(dyn, ninst, 0, x1, x2, x3);
            jump_to_next(dyn, addr, 0, ninst, rex.is32bits);
            ok=0; need_epilog=0;
        }
    }
    if(need_epilog) {
        NOTEST(x3);
        fpu_purgecache(dyn, ninst, 0, x1, x2, x3);
        jump_to_epilog(dyn, ip, 0, ninst);  // no linker here, it's an unknown instruction
    }
    FINI;
    MESSAGE(LOG_DUMP, "---- END OF BLOCK ---- (%d)\n", dyn->size);
    return addr;
}
