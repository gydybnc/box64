#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

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

int isSimpleWrapper(wrapper_t fun);

uintptr_t dynarec64_00_1(dynarec_rv64_t* dyn, uintptr_t addr, uintptr_t ip, int ninst, rex_t rex, int rep, int* ok, int* need_epilog)
{
    uint8_t nextop, opcode;
    uint8_t gd, ed;
    int8_t i8;
    int32_t i32, tmp;
    int64_t i64, j64;
    uint8_t u8;
    uint8_t gb1, gb2, eb1, eb2;
    uint32_t u32;
    uint64_t u64;
    uint8_t wback, wb1, wb2, wb;
    int64_t fixedaddress;
    int lock;
    int cacheupd = 0;

    opcode = F8;
    MAYUSE(eb1);
    MAYUSE(eb2);
    MAYUSE(j64);
    MAYUSE(wb);
    MAYUSE(lock);
    MAYUSE(cacheupd);

    switch(opcode) {
        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
            INST_NAME("INC Reg (32bits)");
            SETFLAGS(X_ALL&~X_CF, SF_SUBSET_PENDING);
            gd = xRAX + (opcode&7);
            emit_inc32(dyn, ninst, rex, gd, x1, x2, x3, x4);
            break;
        case 0x48:
        case 0x49:
        case 0x4A:
        case 0x4B:
        case 0x4C:
        case 0x4D:
        case 0x4E:
        case 0x4F:
            INST_NAME("DEC Reg (32bits)");
            SETFLAGS(X_ALL&~X_CF, SF_SUBSET_PENDING);
            gd = xRAX + (opcode&7);
            emit_dec32(dyn, ninst, rex, gd, x1, x2, x3, x4);
            break;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
            INST_NAME("PUSH reg");
            gd = xRAX+(opcode&0x07)+(rex.b<<3);
            PUSH1z(gd);
            break;
        case 0x58:
        case 0x59:
        case 0x5A:
        case 0x5B:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F:
            INST_NAME("POP reg");
            gd = xRAX+(opcode&0x07)+(rex.b<<3);
            POP1z(gd);
            break;

        case 0x60:
            if(rex.is32bits) {
                INST_NAME("PUSHAD");
                AND(x1, xRSP, xMASK);
                PUSH1_32(xRAX);
                PUSH1_32(xRCX);
                PUSH1_32(xRDX);
                PUSH1_32(xRBX);
                PUSH1_32(x1);
                PUSH1_32(xRBP);
                PUSH1_32(xRSI);
                PUSH1_32(xRDI);
            } else {
                DEFAULT;
            }
            break;
        case 0x61:
            if(rex.is32bits) {
                INST_NAME("POPAD");
                POP1_32(xRDI);
                POP1_32(xRSI);
                POP1_32(xRBP);
                POP1_32(x1);
                POP1_32(xRBX);
                POP1_32(xRDX);
                POP1_32(xRCX);
                POP1_32(xRAX);
            } else {
                DEFAULT;
            }
            break;
        case 0x62:
            if(rex.is32bits) {
                // BOUND here
                DEFAULT;                
            } else {
                INST_NAME("BOUND Gd, Ed");
                nextop = F8;
                FAKEED;
            }
            break;
        case 0x63:
            if(rex.is32bits) {
                // this is ARPL opcode
                DEFAULT;
            } else {
                INST_NAME("MOVSXD Gd, Ed");
                nextop = F8;
                GETGD;
                if(rex.w) {
                    if(MODREG) {   // reg <= reg
                        ADDIW(gd, xRAX+(nextop&7)+(rex.b<<3), 0);
                    } else {                    // mem <= reg
                        SMREAD();
                        addr = geted(dyn, addr, ninst, nextop, &ed, x2, x1, &fixedaddress, rex, NULL, 1, 0);
                        LW(gd, ed, fixedaddress);
                    }
                } else {
                    if(MODREG) {   // reg <= reg
                        AND(gd, xRAX+(nextop&7)+(rex.b<<3), xMASK);
                    } else {                    // mem <= reg
                        SMREAD();
                        addr = geted(dyn, addr, ninst, nextop, &ed, x2, x1, &fixedaddress, rex, NULL, 1, 0);
                        LWU(gd, ed, fixedaddress);
                    }
                }
            }
            break;
        case 0x64:
            addr = dynarec64_64(dyn, addr, ip, ninst, rex, rep, _FS, ok, need_epilog);
            break;
        case 0x65:
            addr = dynarec64_64(dyn, addr, ip, ninst, rex, rep, _GS, ok, need_epilog);
            break;
        case 0x66:
            addr = dynarec64_66(dyn, addr, ip, ninst, rex, rep, ok, need_epilog);
            break;
        case 0x67:
            if(rex.is32bits)
                addr = dynarec64_67_32(dyn, addr, ip, ninst, rex, rep, ok, need_epilog);
            else
                addr = dynarec64_67(dyn, addr, ip, ninst, rex, rep, ok, need_epilog);
            break;
        case 0x68:
            INST_NAME("PUSH Id");
            i64 = F32S;
            if(PK(0)==0xC3) {
                MESSAGE(LOG_DUMP, "PUSH then RET, using indirect\n");
                TABLE64(x3, addr-4);
                LW(x1, x3, 0);
                PUSH1z(x1);
            } else {
                MOV64z(x3, i64);
                PUSH1z(x3);
            }
            break;
        case 0x69:
            INST_NAME("IMUL Gd, Ed, Id");
            SETFLAGS(X_ALL, SF_PENDING);
            nextop = F8;
            GETGD;
            GETED(4);
            i64 = F32S;
            MOV64xw(x4, i64);
            if(rex.w) {
                // 64bits imul
                UFLAG_IF {
                    MULH(x3, ed, x4);
                    MUL(gd, ed, x4);
                    UFLAG_OP1(x3);
                    UFLAG_RES(gd);
                    UFLAG_DF(x3, d_imul64);
                } else {
                    MULxw(gd, ed, x4);
                }
            } else {
                // 32bits imul
                UFLAG_IF {
                    SEXT_W(x3, ed);
                    MUL(gd, x3, x4);
                    UFLAG_RES(gd);
                    SRLI(x3, gd, 32);
                    UFLAG_OP1(x3);
                    UFLAG_DF(x3, d_imul32);
                } else {
                    MULxw(gd, ed, x4);
                }
                ZEROUP(gd);
            }
            break;
        case 0x6A:
            INST_NAME("PUSH Ib");
            i64 = F8S;
            MOV64z(x3, i64);
            PUSH1z(x3);
            break;
        case 0x6B:
            INST_NAME("IMUL Gd, Ed, Ib");
            SETFLAGS(X_ALL, SF_PENDING);
            nextop = F8;
            GETGD;
            GETED(1);
            i64 = F8S;
            MOV64xw(x4, i64);
            if(rex.w) {
                // 64bits imul
                UFLAG_IF {
                    MULH(x3, ed, x4);
                    MUL(gd, ed, x4);
                    UFLAG_OP1(x3);
                    UFLAG_RES(gd);
                    UFLAG_DF(x3, d_imul64);
                } else {
                    MUL(gd, ed, x4);
                }
            } else {
                // 32bits imul
                UFLAG_IF {
                    SEXT_W(x3, ed);
                    MUL(gd, x3, x4);
                    UFLAG_RES(gd);
                    SRLI(x3, gd, 32);
                    UFLAG_OP1(x3);
                    UFLAG_DF(x3, d_imul32);
                } else {
                    MULW(gd, ed, x4);
                }
                ZEROUP(gd);
            }
            break;

        case 0x6C:
        case 0x6D:
            INST_NAME(opcode == 0x6C ? "INSB" : "INSD");
            SETFLAGS(X_ALL, SF_SET_NODF); // Hack to set flags in "don't care" state
            GETIP(ip);
            STORE_XEMU_CALL(x3);
            CALL(native_priv, -1);
            LOAD_XEMU_CALL();
            jump_to_epilog(dyn, 0, xRIP, ninst);
            *need_epilog = 0;
            *ok = 0;
            break;
        case 0x6E:
        case 0x6F:
            INST_NAME(opcode == 0x6C ? "OUTSB" : "OUTSD");
            SETFLAGS(X_ALL, SF_SET_NODF); // Hack to set flags in "don't care" state
            GETIP(ip);
            STORE_XEMU_CALL(x3);
            CALL(native_priv, -1);
            LOAD_XEMU_CALL();
            jump_to_epilog(dyn, 0, xRIP, ninst);
            *need_epilog = 0;
            *ok = 0;
            break;

        #define GO(GETFLAGS, NO, YES, F)                                \
            READFLAGS(F);                                               \
            i8 = F8S;                                                   \
            BARRIER(BARRIER_MAYBE);                                     \
            JUMP(addr+i8, 1);                                           \
            GETFLAGS;                                                   \
            if(dyn->insts[ninst].x64.jmp_insts==-1 ||                   \
                CHECK_CACHE()) {                                        \
                /* out of the block */                                  \
                i32 = dyn->insts[ninst].epilog-(dyn->native_size);      \
                B##NO##_safe(x1, i32);                                  \
                if(dyn->insts[ninst].x64.jmp_insts==-1) {               \
                    if(!(dyn->insts[ninst].x64.barrier&BARRIER_FLOAT))  \
                        fpu_purgecache(dyn, ninst, 1, x1, x2, x3);      \
                    jump_to_next(dyn, addr+i8, 0, ninst, rex.is32bits); \
                } else {                                                \
                    CacheTransform(dyn, ninst, cacheupd, x1, x2, x3);   \
                    i32 = dyn->insts[dyn->insts[ninst].x64.jmp_insts].address-(dyn->native_size);\
                    B(i32);                                             \
                }                                                       \
            } else {                                                    \
                /* inside the block */                                  \
                i32 = dyn->insts[dyn->insts[ninst].x64.jmp_insts].address-(dyn->native_size);    \
                B##YES##_safe(x1, i32);                                 \
            }

        // GOCOND(0x70, "J", "ib");
        case 0x70 + 0x0:
            INST_NAME("JO ib");
            GO(ANDI(x1, xFlags, 1 << F_OF2), EQZ, NEZ, X_OF)
            break;
        case 0x70 + 0x1:
            INST_NAME("JNO ib");
            GO(ANDI(x1, xFlags, 1 << F_OF2), NEZ, EQZ, X_OF)
            break;
        case 0x70 + 0x2:
            INST_NAME("JC ib");
            GO(ANDI(x1, xFlags, 1 << F_CF), EQZ, NEZ, X_CF)
            break;
        case 0x70 + 0x3:
            INST_NAME("JNC ib");
            GO(ANDI(x1, xFlags, 1 << F_CF), NEZ, EQZ, X_CF)
            break;
        case 0x70 + 0x4:
            INST_NAME("JZ ib");
            if (dyn->insts[ninst].pattern_code == 0 || 
                dyn->insts[ninst].pattern_code == 8 || 
                dyn->insts[ninst].pattern_code == 16 ||
                dyn->insts[ninst].pattern_code == 24 ||
                dyn->insts[ninst].pattern_code == 32){
                    //GO(NO,YES)
                    //NEZ=1  EQZ=0
                    //op1=op2 then jmp -> x1==0 -> YES -> GO(NEZ,EQZ)
                GO(SUB(x1, dyn->insts[ninst].op1, dyn->insts[ninst].op2), NEZ, EQZ, X_ZF)
            }
            else{
                GO(ANDI(x1, xFlags, 1 << F_ZF), EQZ, NEZ, X_ZF)
            }
            break;
        case 0x70 + 0x5:
            INST_NAME("JNZ ib");
            // if (dyn->insts[ninst].pattern_code == 1 || 
            //     dyn->insts[ninst].pattern_code == 9 || 
            //     dyn->insts[ninst].pattern_code == 17 ||
            //     dyn->insts[ninst].pattern_code == 25 ||
            //     dyn->insts[ninst].pattern_code == 33){
            //         //GO(NO,YES)
            //         //NEZ=1  EQZ=0
            //         //op1!=op2 then jmp -> x1!=0 -> YES -> GO(EQZ,NEZ)
            //     GO(SUB(x1, dyn->insts[ninst].op1, dyn->insts[ninst].op2), EQZ, NEZ, X_ZF)
            // }
            // else{
                GO(ANDI(x1, xFlags, 1 << F_ZF), NEZ, EQZ, X_ZF)
            // }
            break;
        case 0x70 + 0x6:
            INST_NAME("JBE ib");
            if (dyn->insts[ninst].pattern_code == 6 || 
                dyn->insts[ninst].pattern_code == 14 || 
                dyn->insts[ninst].pattern_code == 22 ||
                dyn->insts[ninst].pattern_code == 30 ||
                dyn->insts[ninst].pattern_code == 38){
                    //op1<=op2 then jmp -> op2<op1 then not jmp
                    //op2<op1 -> x1==1 -> NO -> GO(NEZ,EQZ)
                GO(SLTU(x1, dyn->insts[ninst].op2, dyn->insts[ninst].op1), NEZ, EQZ, X_CF | X_ZF)
            }
            else{
                GO(ANDI(x1, xFlags, (1 << F_CF) | (1 << F_ZF)), EQZ, NEZ, X_CF | X_ZF)
            }
            break;
        case 0x70 + 0x7:
            INST_NAME("JNBE ib");
            if (dyn->insts[ninst].pattern_code == 7 || 
                dyn->insts[ninst].pattern_code == 15 || 
                dyn->insts[ninst].pattern_code == 23 ||
                dyn->insts[ninst].pattern_code == 31 ||
                dyn->insts[ninst].pattern_code == 39){
                    //op1>op2 then jmp -> op2<op1 then jmp
                    //op2<op1 -> x1==1 -> YES -> GO(EQZ,NEZ)
                GO(SLTU(x1, dyn->insts[ninst].op2, dyn->insts[ninst].op1), EQZ, NEZ, X_CF | X_ZF)
            }
            else{
                GO(ANDI(x1, xFlags, (1 << F_CF) | (1 << F_ZF)), NEZ, EQZ, X_CF | X_ZF)
            }
            break;
        case 0x70 + 0x8:
            INST_NAME("JS ib");
            GO(ANDI(x1, xFlags, 1 << F_SF), EQZ, NEZ, X_SF)
            break;
        case 0x70 + 0x9:
            INST_NAME("JNS ib");
            GO(ANDI(x1, xFlags, 1 << F_SF), NEZ, EQZ, X_SF)
            break;
        case 0x70 + 0xA:
            INST_NAME("JP ib");
            GO(ANDI(x1, xFlags, 1 << F_PF), EQZ, NEZ, X_PF)
            break;
        case 0x70 + 0xB:
            INST_NAME("JNP ib");
            GO(ANDI(x1, xFlags, 1 << F_PF), NEZ, EQZ, X_PF)
            break;
        case 0x70 + 0xC:
            INST_NAME("JL ib");
            if (dyn->insts[ninst].pattern_code == 2 || 
                dyn->insts[ninst].pattern_code == 10 || 
                dyn->insts[ninst].pattern_code == 18 ||
                dyn->insts[ninst].pattern_code == 26 ||
                dyn->insts[ninst].pattern_code == 34){
                    //GO(NO,YES)
                    //NEZ=1  EQZ=0
                    //op1<op2 then jmp -> x1==1 -> YES -> GO(EQZ,NEZ)
                GO(SLT(x1, dyn->insts[ninst].op1, dyn->insts[ninst].op2), EQZ, NEZ, X_SF | X_OF)
            }
            else{
                GO(SRLI(x1, xFlags, F_SF - F_OF2);
                    XOR(x1, x1, xFlags);
                    ANDI(x1, x1, 1 << F_OF2), EQZ, NEZ, X_SF | X_OF)
            }
            break;
        case 0x70 + 0xD:
            INST_NAME("JGE ib");
            if (dyn->insts[ninst].pattern_code == 3 || 
                dyn->insts[ninst].pattern_code == 11 || 
                dyn->insts[ninst].pattern_code == 19 ||
                dyn->insts[ninst].pattern_code == 27 ||
                dyn->insts[ninst].pattern_code == 35) {
                    //op1>=op2 then jmp -> op1<op2 then not jmp
                    //op1<op2 -> x1 == 1 -> NO -> GO(NEZ,EQZ)
                GO(SLT(x1, dyn->insts[ninst].op1, dyn->insts[ninst].op2), NEZ, EQZ, X_SF | X_OF)
            }
            else{
                GO(SRLI(x1, xFlags, F_SF - F_OF2);
                    XOR(x1, x1, xFlags);
                    ANDI(x1, x1, 1 << F_OF2), NEZ, EQZ, X_SF | X_OF)
            }
            break;
        case 0x70 + 0xE:
            INST_NAME("JLE ib");
            if (dyn->insts[ninst].pattern_code == 4 || 
                dyn->insts[ninst].pattern_code == 12 || 
                dyn->insts[ninst].pattern_code == 20 ||
                dyn->insts[ninst].pattern_code == 28 ||
                dyn->insts[ninst].pattern_code == 36) {
                    //op1<=op2 then jmp -> op2<op1 then not jmp
                    //op2<op1 -> x1 == 1 -> NO -> GO(NEZ,EQZ)
                GO(SLT(x1, dyn->insts[ninst].op2, dyn->insts[ninst].op1), NEZ, EQZ, X_SF | X_OF | X_ZF)
            }
            else{
                GO(SRLI(x1, xFlags, F_SF - F_OF2);
                    XOR(x1, x1, xFlags);
                    ANDI(x1, x1, 1 << F_OF2);
                    ANDI(x3, xFlags, 1 << F_ZF);
                    OR(x1, x1, x3);
                    ANDI(x1, x1, (1 << F_OF2) | (1 << F_ZF)), EQZ, NEZ, X_SF | X_OF | X_ZF)
            }
            break;
        case 0x70 + 0xF:
            INST_NAME("JG ib");
            if (dyn->insts[ninst].pattern_code == 5 || 
                dyn->insts[ninst].pattern_code == 13 || 
                dyn->insts[ninst].pattern_code == 21 ||
                dyn->insts[ninst].pattern_code == 29 ||
                dyn->insts[ninst].pattern_code == 37){
                    //op1>op2 then jmp -> op2<op1 then jmp
                    //op2<op1 -> x1 == 1 -> YES -> GO(EQZ,NEZ)
                GO(SLT(x1, dyn->insts[ninst].op2, dyn->insts[ninst].op1), EQZ, NEZ, X_SF | X_OF | X_ZF)
            }
            else{
                GO(SRLI(x1, xFlags, F_SF - F_OF2);
                    XOR(x1, x1, xFlags);
                    ANDI(x1, x1, 1 << F_OF2);
                    ANDI(x3, xFlags, 1 << F_ZF);
                    OR(x1, x1, x3);
                    ANDI(x1, x1, (1 << F_OF2) | (1 << F_ZF)), NEZ, EQZ, X_SF | X_OF | X_ZF)
            }
            break;

        #undef GO
        default:
            DEFAULT;
    }

     return addr;
}
