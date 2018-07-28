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
package ca.mcgill.sis.dmas.kam1n0.vex.guest;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;

public class GuestAMD64 extends Guest {
	public GuestAMD64() {
		registerName.put(0, "host_evc_failaddr");
		registerName.put(8, "host_evc_counter");
		registerName.put(12, "pad0");
		registerName.put(16, "rax");
		registerName.put(24, "rcx");
		registerName.put(32, "rdx");
		registerName.put(40, "rbx");
		registerName.put(48, "rsp");
		registerName.put(56, "rbp");
		registerName.put(64, "rsi");
		registerName.put(72, "rdi");
		registerName.put(80, "r8");
		registerName.put(88, "r9");
		registerName.put(96, "r10");
		registerName.put(104, "r11");
		registerName.put(112, "r12");
		registerName.put(120, "r13");
		registerName.put(128, "r14");
		registerName.put(136, "r15");
		registerName.put(144, "cc_op");
		registerName.put(152, "cc_dep1");
		registerName.put(160, "cc_dep2");
		registerName.put(168, "cc_ndep");
		registerName.put(176, "dflag");
		registerName.put(184, "rip");
		registerName.put(192, "acflag");
		registerName.put(200, "idflag");
		registerName.put(208, "fs_const");
		registerName.put(216, "sseround");
		registerName.put(224, "ymm0");
		registerName.put(256, "ymm1");
		registerName.put(288, "ymm2");
		registerName.put(320, "ymm3");
		registerName.put(352, "ymm4");
		registerName.put(384, "ymm5");
		registerName.put(416, "ymm6");
		registerName.put(448, "ymm7");
		registerName.put(480, "ymm8");
		registerName.put(512, "ymm9");
		registerName.put(544, "ymm10");
		registerName.put(576, "ymm11");
		registerName.put(608, "ymm12");
		registerName.put(640, "ymm13");
		registerName.put(672, "ymm14");
		registerName.put(704, "ymm15");
		registerName.put(736, "ymm16");
		registerName.put(768, "ftop");
		registerName.put(772, "pad1");
		registerName.put(776, "mm0");
		registerName.put(784, "mm1");
		registerName.put(792, "mm2");
		registerName.put(800, "mm3");
		registerName.put(808, "mm4");
		registerName.put(816, "mm5");
		registerName.put(824, "mm6");
		registerName.put(832, "mm7");
		registerName.put(840, "fpu_tags");
		registerName.put(848, "fpround");
		registerName.put(856, "fc3210");
		registerName.put(864, "emnote");
		registerName.put(868, "pad2");
		registerName.put(872, "cmstart");
		registerName.put(880, "cmlen");
		registerName.put(888, "nraddr");
		registerName.put(896, "sc_class");
		registerName.put(904, "gs_const");
		registerName.put(912, "ip_at_syscall");
		registerName.put(920, "pad3");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 136 && index >= 16) || (index <= 832 && index >= 224) || (index == 184));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchAMD64;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 184;
	}

}
