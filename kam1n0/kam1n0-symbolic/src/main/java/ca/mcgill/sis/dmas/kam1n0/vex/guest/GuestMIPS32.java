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

public class GuestMIPS32 extends Guest {
	public GuestMIPS32() {
		registerName.put(0, "zero");
		registerName.put(4, "at");
		registerName.put(8, "v0");
		registerName.put(12, "v1");
		registerName.put(16, "a0");
		registerName.put(20, "a1");
		registerName.put(24, "a2");
		registerName.put(28, "a3");
		registerName.put(32, "t0");
		registerName.put(36, "t1");
		registerName.put(40, "t2");
		registerName.put(44, "t3");
		registerName.put(48, "t4");
		registerName.put(52, "t5");
		registerName.put(56, "t6");
		registerName.put(60, "t7");
		registerName.put(64, "s0");
		registerName.put(68, "s1");
		registerName.put(72, "s2");
		registerName.put(76, "s3");
		registerName.put(80, "s4");
		registerName.put(84, "s5");
		registerName.put(88, "s6");
		registerName.put(92, "s7");
		registerName.put(96, "t8");
		registerName.put(100, "t9");
		registerName.put(104, "k0");
		registerName.put(108, "k1");
		registerName.put(112, "gp");
		registerName.put(116, "sp");
		registerName.put(120, "s8");
		registerName.put(124, "ra");

		registerName.put(128, "pc");

		registerName.put(132, "hi");
		registerName.put(136, "lo");

		registerName.put(144, "f0");
		registerName.put(152, "f1");
		registerName.put(160, "f2");
		registerName.put(168, "f3");
		registerName.put(176, "f4");
		registerName.put(184, "f5");
		registerName.put(192, "f6");
		registerName.put(200, "f7");
		registerName.put(208, "f8");
		registerName.put(216, "f9");
		registerName.put(224, "f10");
		registerName.put(232, "f11");
		registerName.put(240, "f12");
		registerName.put(248, "f13");
		registerName.put(256, "f14");
		registerName.put(264, "f15");
		registerName.put(272, "f16");
		registerName.put(280, "f17");
		registerName.put(288, "f18");
		registerName.put(296, "f19");
		registerName.put(304, "f20");
		registerName.put(312, "f21");
		registerName.put(320, "f22");
		registerName.put(328, "f23");
		registerName.put(336, "f24");
		registerName.put(344, "f25");
		registerName.put(352, "f26");
		registerName.put(360, "f27");
		registerName.put(368, "f28");
		registerName.put(376, "f29");
		registerName.put(384, "f30");
		registerName.put(392, "f31");
		registerName.put(400, "fir");
		registerName.put(404, "fccr");
		registerName.put(408, "fexr");
		registerName.put(412, "fenr");
		registerName.put(416, "fcsr");
		registerName.put(420, "ulr");
		registerName.put(424, "emnote");
		registerName.put(428, "cmstart");
		registerName.put(432, "cmlen");
		registerName.put(436, "nraddr");
		registerName.put(440, "evc_failaddr");
		registerName.put(444, "evc_counter");
		registerName.put(448, "cond");
		registerName.put(452, "dspcontrol");
		registerName.put(456, "ac0");
		registerName.put(464, "ac1");
		registerName.put(472, "ac2");
		registerName.put(480, "ac3");
		registerName.put(488, "ip_at_syscall");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 124 && index >= 8) || (index <= 392 && index >= 132) || (index == 128));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchMIPS32;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 128;
	}
}
