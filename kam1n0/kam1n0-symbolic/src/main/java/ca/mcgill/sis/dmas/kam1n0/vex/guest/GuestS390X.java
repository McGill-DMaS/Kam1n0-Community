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

public class GuestS390X extends Guest {
	public GuestS390X() {
		registerName.put(0, "a0");
		registerName.put(4, "a1");
		registerName.put(8, "a2");
		registerName.put(12, "a3");
		registerName.put(16, "a4");
		registerName.put(20, "a5");
		registerName.put(24, "a6");
		registerName.put(28, "a7");
		registerName.put(32, "a8");
		registerName.put(36, "a9");
		registerName.put(40, "a10");
		registerName.put(44, "a11");
		registerName.put(48, "a12");
		registerName.put(52, "a13");
		registerName.put(56, "a14");
		registerName.put(60, "a15");

		registerName.put(64, "f0");
		registerName.put(72, "f1");
		registerName.put(80, "f2");
		registerName.put(88, "f3");
		registerName.put(96, "f4");
		registerName.put(104, "f5");
		registerName.put(112, "f6");
		registerName.put(120, "f7");
		registerName.put(128, "f8");
		registerName.put(136, "f9");
		registerName.put(144, "f10");
		registerName.put(152, "f11");
		registerName.put(160, "f12");
		registerName.put(168, "f13");
		registerName.put(176, "f14");
		registerName.put(184, "f15");

		registerName.put(192, "r0");
		registerName.put(200, "r1");
		registerName.put(208, "r2");
		registerName.put(216, "r3");
		registerName.put(224, "r4");
		registerName.put(232, "r5");
		registerName.put(240, "r6");
		registerName.put(248, "r7");
		registerName.put(256, "r8");
		registerName.put(264, "r9");
		registerName.put(272, "r10");
		registerName.put(280, "r11");
		registerName.put(288, "r12");
		registerName.put(296, "r13");
		registerName.put(304, "r14");
		registerName.put(312, "r15");

		registerName.put(320, "counter");
		registerName.put(328, "fpc");
		registerName.put(336, "IA");

		registerName.put(344, "SYSNO");

		registerName.put(352, "CC_OP");
		registerName.put(360, "CC_DEP1");
		registerName.put(368, "CC_DEP2");
		registerName.put(376, "CC_NDEP");

		registerName.put(384, "NRADDR");
		registerName.put(392, "CMSTART");
		registerName.put(400, "CMLEN");

		registerName.put(408, "IP_AT_SYSCALL");
		registerName.put(416, "EMNOTE");

		registerName.put(420, "host_EvC_COUNTER");
		registerName.put(424, "host_EvC_FAILADDR");

		registerName.put(432, "padding0");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 320 && index >= 0) || (index == 184));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchS390X;
	}

	@Override
	public boolean isProgramCounter(int index) {
		// TODO: double check
		return index == 320;
	}
}
