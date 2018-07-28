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

public class GuestARM extends Guest {
	public GuestARM() {
		registerName.put(8, "r0");
		registerName.put(12, "r1");
		registerName.put(16, "r2");
		registerName.put(20, "r3");
		registerName.put(24, "r4");
		registerName.put(28, "r5");
		registerName.put(32, "r6");
		registerName.put(36, "r7");
		registerName.put(40, "r8");
		registerName.put(44, "r9");
		registerName.put(48, "r10");
		registerName.put(52, "r11");
		registerName.put(56, "r12");

		registerName.put(60, "sp");

		registerName.put(64, "lr");

		registerName.put(68, "pc");

		registerName.put(72, "cc_op");
		registerName.put(76, "cc_dep1");
		registerName.put(80, "cc_dep2");
		registerName.put(84, "cc_ndep");

		registerName.put(88, "qflag32");
		registerName.put(92, "geflag0");
		registerName.put(96, "geflag1");
		registerName.put(100, "geflag2");
		registerName.put(104, "geflag3");

		registerName.put(108, "emnote");
		registerName.put(112, "cmstart");
		registerName.put(116, "cmlen");
		registerName.put(120, "nraddr");
		registerName.put(124, "ip_at_syscall");

		registerName.put(128, "d0");
		registerName.put(136, "d1");
		registerName.put(144, "d2");
		registerName.put(152, "d3");
		registerName.put(160, "d4");
		registerName.put(168, "d5");
		registerName.put(176, "d6");
		registerName.put(184, "d7");
		registerName.put(192, "d8");
		registerName.put(200, "d9");
		registerName.put(208, "d10");
		registerName.put(216, "d11");
		registerName.put(224, "d12");
		registerName.put(232, "d13");
		registerName.put(240, "d14");
		registerName.put(248, "d15");
		registerName.put(256, "d16");
		registerName.put(264, "d17");
		registerName.put(272, "d18");
		registerName.put(280, "d19");
		registerName.put(288, "d20");
		registerName.put(296, "d21");
		registerName.put(304, "d22");
		registerName.put(312, "d23");
		registerName.put(320, "d24");
		registerName.put(328, "d25");
		registerName.put(336, "d26");
		registerName.put(344, "d27");
		registerName.put(352, "d28");
		registerName.put(360, "d29");
		registerName.put(368, "d30");
		registerName.put(376, "d31");

		registerName.put(384, "fpscr");
		registerName.put(388, "tpidruro");
		registerName.put(392, "itstate");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 60 && index >= 0) || (index <= 376 && index >= 128) || (index == 68));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchARM;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 68;
	}
}
