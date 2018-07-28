
/*---------------------------------------------------------------*/
/*--- begin                              libvex_guest_arm64.h ---*/
/*---------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2013-2013 OpenWorks
      info@open-works.net

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef __LIBVEX_PUB_GUEST_ARM64_H
#define __LIBVEX_PUB_GUEST_ARM64_H

#include "libvex_basictypes.h"


/*---------------------------------------------------------------*/
/*--- Vex's representation of the ARM64 CPU state.            ---*/
/*---------------------------------------------------------------*/

typedef
   struct {
      /* Event check fail addr and counter. */
      /*   0 */ ULong host_EvC_FAILADDR;
      /*   8 */ UInt  host_EvC_COUNTER;
      /*  12 */ UInt  pad0;

      /*  16 */ ULong guest_X0;
      /*  24 */ ULong guest_X1;
      /*  32 */ ULong guest_X2;
      /*  40 */ ULong guest_X3;
      /*  48 */ ULong guest_X4;
      /*  56 */ ULong guest_X5;
      /*  64 */ ULong guest_X6;
      /*  72 */ ULong guest_X7;
      /*  80 */ ULong guest_X8;
      /*  88 */ ULong guest_X9;
      /*  96 */ ULong guest_X10;
      /* 104 */ ULong guest_X11;
      /* 112 */ ULong guest_X12;
      /* 120 */ ULong guest_X13;
      /* 128 */ ULong guest_X14;
      /* 136 */ ULong guest_X15;
      /* 144 */ ULong guest_X16;
      /* 152 */ ULong guest_X17;
      /* 160 */ ULong guest_X18;
      /* 168 */ ULong guest_X19;
      /* 176 */ ULong guest_X20;
      /* 184 */ ULong guest_X21;
      /* 192 */ ULong guest_X22;
      /* 200 */ ULong guest_X23;
      /* 208 */ ULong guest_X24;
      /* 216 */ ULong guest_X25;
      /* 224 */ ULong guest_X26;
      /* 232 */ ULong guest_X27;
      /* 240 */ ULong guest_X28;
      /* 248 */ ULong guest_X29;
      /* 256 */ ULong guest_X30;     /* link register */
      /* 264 */ ULong guest_XSP;
      /* 272 */ ULong guest_PC;

      /* 4-word thunk used to calculate N(sign) Z(zero) C(carry,
         unsigned overflow) and V(signed overflow) flags. */
      /* 280 */ ULong guest_CC_OP;
      /* 288 */ ULong guest_CC_DEP1;
      /* 296 */ ULong guest_CC_DEP2;
      /* 304 */ ULong guest_CC_NDEP;

      /* User-space thread register? */
      /* 312 */ ULong guest_TPIDR_EL0;

      /* FP/SIMD state */
      /* 320 */ U128 guest_Q0;
      /* 336 */ U128 guest_Q1;
      /* 352 */ U128 guest_Q2;
      /* 368 */ U128 guest_Q3;
      /* 384 */ U128 guest_Q4;
      /* 400 */ U128 guest_Q5;
      /* 416 */ U128 guest_Q6;
      /* 432 */ U128 guest_Q7;
      /* 448 */ U128 guest_Q8;
      /* 464 */ U128 guest_Q9;
      /* 480 */ U128 guest_Q10;
      /* 496 */ U128 guest_Q11;
      /* 512 */ U128 guest_Q12;
      /* 528 */ U128 guest_Q13;
      /* 544 */ U128 guest_Q14;
      /* 560 */ U128 guest_Q15;
      /* 576 */ U128 guest_Q16;
      /* 592 */ U128 guest_Q17;
      /* 608 */ U128 guest_Q18;
      /* 624 */ U128 guest_Q19;
      /* 640 */ U128 guest_Q20;
      /* 656 */ U128 guest_Q21;
      /* 672 */ U128 guest_Q22;
      /* 688 */ U128 guest_Q23;
      /* 704 */ U128 guest_Q24;
      /* 720 */ U128 guest_Q25;
      /* 736 */ U128 guest_Q26;
      /* 752 */ U128 guest_Q27;
      /* 768 */ U128 guest_Q28;
      /* 784 */ U128 guest_Q29;
      /* 800 */ U128 guest_Q30;
      /* 816 */ U128 guest_Q31;

      /* A 128-bit value which is used to represent the FPSR.QC (sticky
         saturation) flag, when necessary.  If the value stored here
         is zero, FPSR.QC is currently zero.  If it is any other value,
         FPSR.QC is currently one.  We don't currently represent any 
         other bits of FPSR, so this is all that that is for FPSR. */
      /* 832 */ U128 guest_QCFLAG;

      /* Various pseudo-regs mandated by Vex or Valgrind. */
      /* Emulation notes */
      /* 848 */ UInt guest_EMNOTE;

      /* For clflush/clinval: record start and length of area */
      /* 852 */ ULong guest_CMSTART;
      /* 860 */ ULong guest_CMLEN;

      /* Used to record the unredirected guest address at the start of
         a translation whose start has been redirected.  By reading
         this pseudo-register shortly afterwards, the translation can
         find out what the corresponding no-redirection address was.
         Note, this is only set for wrap-style redirects, not for
         replace-style ones. */
      /* 868 */ ULong guest_NRADDR;

      /* Needed for Darwin (but mandated for all guest architectures):
         program counter at the last syscall insn (int 0x80/81/82,
         sysenter, syscall, svc).  Used when backing up to restart a
         syscall that has been interrupted by a signal. */
      /* 876 */ ULong guest_IP_AT_SYSCALL;

      /* The complete FPCR.  Default value seems to be zero.  We
         ignore all bits except 23 and 22, which are the rounding
         mode.  The guest is unconstrained in what values it can write
         to and read from this register, but the emulation only takes
         note of bits 23 and 22. */
      /* 884 */ UInt  guest_FPCR;

      /* Padding to make it have an 16-aligned size */
      /* UInt  pad_end_0; */
      /* ULong pad_end_1; */
   }  /* 888 */
   VexGuestARM64State;


/*---------------------------------------------------------------*/
/*--- Utility functions for ARM64 guest stuff.                ---*/
/*---------------------------------------------------------------*/

/* ALL THE FOLLOWING ARE VISIBLE TO LIBRARY CLIENT */

/* Initialise all guest ARM64 state. */

extern
void LibVEX_GuestARM64_initialise ( /*OUT*/VexGuestARM64State* vex_state );

/* Calculate the ARM64 flag state from the saved data, in the format
   32x0:n:z:c:v:28x0. */
extern
ULong LibVEX_GuestARM64_get_nzcv ( /*IN*/
                                   const VexGuestARM64State* vex_state );

/* Calculate the ARM64 FPSR state from the saved data, in the format
   36x0:qc:27x0 */
extern
ULong LibVEX_GuestARM64_get_fpsr ( /*IN*/
                                   const VexGuestARM64State* vex_state );

/* Set the ARM64 FPSR representation from the given FPSR value. */
extern
void LibVEX_GuestARM64_set_fpsr ( /*MOD*/VexGuestARM64State* vex_state,
                                  ULong fpsr );
                                  

#endif /* ndef __LIBVEX_PUB_GUEST_ARM64_H */


/*---------------------------------------------------------------*/
/*---                                    libvex_guest_arm64.h ---*/
/*---------------------------------------------------------------*/
