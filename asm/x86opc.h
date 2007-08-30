/* 
 *	HT Editor
 *	x86opc.h
 *
 *	Copyright (C) 1999-2002 Stefan Weyergraf
 *	Copyright (C) 2005-2006 Sebastian Biallas (sb@biallas.net)
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __X86OPC_H__
#define __X86OPC_H__

#include "io/types.h"

#define X86_PREFIX_NO		-1

#define X86_PREFIX_LOCK		0	/* f0 */

#define X86_PREFIX_ES		0	/* 26 */
#define X86_PREFIX_CS		1	/* 2e */
#define X86_PREFIX_SS		2	/* 36 */
#define X86_PREFIX_DS		3	/* 3e */
#define X86_PREFIX_FS		4	/* 64 */
#define X86_PREFIX_GS		5	/* 65 */

#define X86_PREFIX_REPNZ	0	/* f2 */
#define X86_PREFIX_REPZ		1	/* f3 */

#define X86_PREFIX_OPSIZE	0	/* 66 */
#define X86_PREFIX_NOOPSIZE	1	/* no 66 allowed */

enum X86OpSize {
	X86_OPSIZEUNKNOWN = -1,
	X86_OPSIZE16 = 0,
	X86_OPSIZE32 = 1,
	X86_OPSIZE64 = 2,
};

enum X86AddrSize {
	X86_ADDRSIZEUNKNOWN = -1,
	X86_ADDRSIZE16 = 0,
	X86_ADDRSIZE32 = 1,
	X86_ADDRSIZE64 = 2,
};

#define X86_OPTYPE_EMPTY	0
#define X86_OPTYPE_IMM		1
#define X86_OPTYPE_REG		2
#define X86_OPTYPE_SEG		3
#define X86_OPTYPE_MEM		4
#define X86_OPTYPE_CRX		5
#define X86_OPTYPE_DRX		6
#define X86_OPTYPE_TRX		7
#define X86_OPTYPE_STX		8
#define X86_OPTYPE_MMX		9
#define X86_OPTYPE_XMM		10
#define X86_OPTYPE_FARPTR	11

// user defined types start here
#define X86_OPTYPE_USER		32

struct x86_insn_op {
	int type;
	int size;
	bool need_rex;
	bool forbid_rex;
	union {
		struct {
			uint32 seg;
			uint32 offset;
		} farptr;			
		uint64 imm;
		int reg;
		int seg;
		struct {
			uint64 disp;
			int base;
			int index;
			int scale;
			int addrsize;
			bool floatptr;
			bool addrptr;
			bool hasdisp;
		} mem;
		int crx;
		int drx;
		int trx;
		int stx;
		int mmx;
		int xmm;
		union {
			int i;
			void *p;
		} user[4];
	};
};

enum {
	TYPE_0 = 0,		
	TYPE_A,		/* direct address without ModR/M (generally */
			/* like imm, but can be 16:32 = 48 bit) */
	TYPE_C,		/* reg of ModR/M picks control register */
	TYPE_D,		/* reg of ModR/M picks debug register */
	TYPE_E,		/* ModR/M (general reg or memory) */
	TYPE_F,		/* r/m of ModR/M picks a fpu register */
	TYPE_Fx,	/* extra picks a fpu register */
	TYPE_G,		/* reg of ModR/M picks general register */
	TYPE_Is,	/* signed immediate */
	TYPE_I,		/* unsigned immediate */
	TYPE_Ix,	/* fixed immediate */
	TYPE_J,		/* relative branch offset */
	TYPE_M,		/* ModR/M (memory only) */
	TYPE_MR,	/* Same as E, but extra picks reg size */
	TYPE_O,		/* direct memory without ModR/M */
	TYPE_P,		/* reg of ModR/M picks MMX register */
	TYPE_PR,	/* rm of ModR/M picks MMX register */
	TYPE_Q,		/* ModR/M (MMX reg or memory) */
	TYPE_R,		/* rm of ModR/M picks general register */
	TYPE_Rx,	/* extra picks register */
	TYPE_RXx,	/* extra picks register, no REX extension */
	TYPE_S,		/* reg of ModR/M picks segment register */
	TYPE_Sx,	/* extra picks segment register */
	TYPE_T,		/* reg of ModR/M picks test register */
	TYPE_V,		/* reg of ModR/M picks XMM register */
	TYPE_Vx,	/* extra picks XMM register */
	TYPE_VR,	/* rm of ModR/M picks XMM register */
	TYPE_W,		/* ModR/M (XMM reg or memory) */	
	TYPE_VD,	/* SSE5: src/dest (xmm reg) */
	TYPE_VS0,	/* SSE5: src1 (mod/rm) */
	TYPE_VS1,	/* SSE5: src2 (mod/rm) */
};

/* when name is == 0, the first op has a special meaning (layout see x86_insn_op_special) */
#define SPECIAL_TYPE_INVALID		0
#define SPECIAL_TYPE_PREFIX 		1
#define SPECIAL_TYPE_OPC_GROUP 		2
#define SPECIAL_TYPE_GROUP 		3
#define SPECIAL_TYPE_SGROUP 		4
#define SPECIAL_TYPE_FGROUP 		5

enum {
	SIZE_0 = '0',		/* size unimportant */
	SIZE_B = 'b',		/* byte */
	SIZE_BV = 'B',		/* byte, extended to SIZE_V */
	SIZE_W = 'w',		/* word */
	SIZE_D = 'd',		/* dword */
	SIZE_Q = 'q',		/* qword */
	SIZE_U = 'u',		/* qword OR oword (depending on 0x66 prefix) */
	SIZE_Z = 'z',		/* dword OR qword (depending on 0x66 prefix) */
	SIZE_O = 'o',		/* oword */
	SIZE_V = 'v',		/* word OR dword OR qword */
	SIZE_VV = 'V',		/* word OR dword OR sign extended dword */
	SIZE_R = 'r',		/* dword OR qword (depending on rex size) */
	SIZE_P = 'p',		/* word:word OR word:dword, memory only! */
	SIZE_S = 's',		/* short/single real (32-bit) */
	SIZE_L = 'l',		/* long/double real (64-bit) */
	SIZE_T = 't',		/* temp/extended real (80-bit) */
	SIZE_A = 'a',		/* packed decimal (80-bit BCD) */
};

#define INFO_DEFAULT_64		0x80

struct x86opc_insn_op {
	byte type;
	byte extra;
	byte info;
	byte size;
};

struct x86opc_insn {
	const char *name;
	byte op[4];
};

struct x86_64_insn_patch {
	int opc;
	x86opc_insn insn;
};

/* this can be a group (group!=0), an insn (group==0) && (insn.name!=0) or
   (otherwise) a reserved instruction. */
struct x86opc_finsn {
	x86opc_insn *group;	
	x86opc_insn insn;
};

#define X86_REG_INVALID		-2
#define X86_REG_NO		(-1 & ~8)
#define X86_REG_AX		0
#define X86_REG_CX		1
#define X86_REG_DX		2
#define X86_REG_BX		3
#define X86_REG_SP		4
#define X86_REG_BP		5
#define X86_REG_SI		6
#define X86_REG_DI		7
#define X86_REG_R8		8
#define X86_REG_R9		9
#define X86_REG_R10		10
#define X86_REG_R11		11
#define X86_REG_R12		12
#define X86_REG_R13		13
#define X86_REG_R14		14
#define X86_REG_R15		15
#define X86_REG_IP		66

#define X86_OPC_GROUPS		9
#define X86_GROUPS		27
#define X86_SPECIAL_GROUPS	7

extern const char *x86_regs[4][8];
extern const char *x86_64regs[4][16];
extern const char *x86_ipregs[4];
extern const char *x86_segs[8];
extern x86opc_insn_op x86_op_type[];
extern x86opc_insn x86_32_insns[256];
extern x86_64_insn_patch x86_64_insn_patches[];
extern x86opc_insn x86_insns_ext[256];
extern x86opc_insn x86_insns_ext_66[256];
extern x86opc_insn x86_insns_ext_f2[256];
extern x86opc_insn x86_insns_ext_f3[256];
extern x86opc_insn x86_opc_group_insns[X86_OPC_GROUPS][256];
extern x86opc_insn x86_group_insns[X86_GROUPS][8];
extern x86opc_insn x86_special_group_insns[X86_SPECIAL_GROUPS][9];

extern x86opc_insn x86_modfloat_group_insns[8][8];
extern x86opc_finsn x86_float_group_insns[8][8];

#endif /* __X86OPC_H__ */
