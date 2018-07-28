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

public class GuestX86 extends Guest {

	public GuestX86() {
		registerName.put(8, "eax");
		registerName.put(12, "ecx");
		registerName.put(16, "edx");
		registerName.put(20, "ebx");

		registerName.put(24, "esp");

		registerName.put(28, "ebp");
		registerName.put(32, "esi");
		registerName.put(36, "edi");

		registerName.put(40, "cc_op");
		registerName.put(44, "cc_dep1");
		registerName.put(48, "cc_dep2");
		registerName.put(52, "cc_ndep");

		registerName.put(56, "d");

		registerName.put(60, "id");
		registerName.put(64, "ac");

		registerName.put(68, "eip");

		registerName.put(72, "mm0");
		registerName.put(80, "mm1");
		registerName.put(88, "mm2");
		registerName.put(96, "mm3");
		registerName.put(104, "mm4");
		registerName.put(112, "mm5");
		registerName.put(120, "mm6");
		registerName.put(128, "mm7");
		registerName.put(136, "fpu_tags");

		registerName.put(144, "fpround");
		registerName.put(148, "fc3210");
		registerName.put(152, "ftop");

		registerName.put(156, "sseround");
		registerName.put(160, "xmm0");
		registerName.put(176, "xmm1");
		registerName.put(192, "xmm2");
		registerName.put(208, "xmm3");
		registerName.put(224, "xmm4");
		registerName.put(240, "xmm5");
		registerName.put(256, "xmm6");
		registerName.put(272, "xmm7");

		registerName.put(288, "cs");
		registerName.put(290, "ds");
		registerName.put(292, "es");
		registerName.put(294, "fs");
		registerName.put(296, "gs");
		registerName.put(298, "ss");

		registerName.put(304, "ldt");
		registerName.put(312, "gdt");

		registerName.put(320, "emnote");
		registerName.put(324, "cmstart");
		registerName.put(328, "cmlen");
		registerName.put(332, "nraddr");
		registerName.put(336, "sc_class");
		registerName.put(340, "ip_at_syscall");
		registerName.put(344, "padding1");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 38 && index >= 8) || (index <= 128 && index >= 72) || (index <= 272 && index >= 160)
				|| (index == 68));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchX86;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 68;
	}

}
