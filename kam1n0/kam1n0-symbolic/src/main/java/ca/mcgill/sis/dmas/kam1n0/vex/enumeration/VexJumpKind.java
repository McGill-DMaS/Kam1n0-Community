/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.vex.enumeration;

import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;

public enum VexJumpKind {
	Ijk_INVALID, Ijk_Boring, /* not interesting; just goto next */
	Ijk_Call, /* guest is doing a call */
	Ijk_Ret, /* guest is doing a return */
	Ijk_ClientReq, /* do guest client req before continuing */
	Ijk_Yield, /* client is yielding to thread scheduler */
	Ijk_EmWarn, /* report emulation warning before continuing */
	Ijk_EmFail, /* emulation critical (FATAL) error; give up */
	Ijk_NoDecode, /* current instruction cannot be decoded */
	Ijk_MapFail, /* Vex-provided address translation failed */
	Ijk_InvalICache, /* Inval icache for range [CMSTART, +CMLEN) */
	Ijk_FlushDCache, /* Flush dcache for range [CMSTART, +CMLEN) */
	Ijk_NoRedir, /* Jump to un-redirected guest addr */
	Ijk_SigILL, /* current instruction synths SIGILL */
	Ijk_SigTRAP, /* current instruction synths SIGTRAP */
	Ijk_SigSEGV, /* current instruction synths SIGSEGV */
	Ijk_SigBUS, /* current instruction synths SIGBUS */
	Ijk_SigFPE_IntDiv, /* current instruction synths SIGFPE - IntDiv */
	Ijk_SigFPE_IntOvf, /* current instruction synths SIGFPE - IntOvf */
	/*
	 * Unfortunately, various guest-dependent syscall kinds. They all mean: do a
	 * syscall before continuing.
	 */
	Ijk_Sys_syscall, /* amd64/x86 'syscall', ppc 'sc', arm 'svc #0' */
	Ijk_Sys_int32, /* amd64/x86 'int $0x20' */
	Ijk_Sys_int128, /* amd64/x86 'int $0x80' */
	Ijk_Sys_int129, /* amd64/x86 'int $0x81' */
	Ijk_Sys_int130, /* amd64/x86 'int $0x82' */
	Ijk_Sys_int145, /* amd64/x86 'int $0x91' */
	Ijk_Sys_int210, /* amd64/x86 'int $0xD2' */
	Ijk_Sys_sysenter /*
						 * x86 'sysenter'. guest_EIP becomes invalid at the
						 * point this happens.
						 */;
	public static int startValue(){
		return 0x1A00;
	}

	
	public static VexJumpKind fromInteger(int index) {
		return VexEnumeration.retrieveType(index, VexJumpKind.class);
	}

}
