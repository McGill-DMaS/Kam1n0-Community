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

public class GuestMIPS64 extends Guest {
	public GuestMIPS64() {
		registerName.put(0, "zero");
		registerName.put(8, "at");
		registerName.put(16, "v0");
		registerName.put(24, "v1");
		registerName.put(32, "a0");
		registerName.put(40, "a1");
		registerName.put(48, "a2");
		registerName.put(56, "a3");
		registerName.put(64, "t0");
		registerName.put(72, "t1");
		registerName.put(80, "t2");
		registerName.put(88, "t3");
		registerName.put(96, "t4");
		registerName.put(104, "t5");
		registerName.put(112, "t6");
		registerName.put(120, "t7");
		registerName.put(128, "s0");
		registerName.put(136, "s1");
		registerName.put(144, "s2");
		registerName.put(152, "s3");
		registerName.put(160, "s4");
		registerName.put(168, "s5");
		registerName.put(176, "s6");
		registerName.put(184, "s7");
		registerName.put(192, "t8");
		registerName.put(200, "t9");
		registerName.put(208, "k0");
		registerName.put(216, "k1");
		registerName.put(224, "gp");
		registerName.put(232, "sp");
		registerName.put(240, "s8");
		registerName.put(248, "ra");
		registerName.put(256, "ip");
		registerName.put(264, "hi");
		registerName.put(272, "lo");
		registerName.put(280, "f0");
		registerName.put(288, "f1");
		registerName.put(296, "f2");
		registerName.put(304, "f3");
		registerName.put(312, "f4");
		registerName.put(320, "f5");
		registerName.put(328, "f6");
		registerName.put(336, "f7");
		registerName.put(344, "f8");
		registerName.put(352, "f9");
		registerName.put(360, "f10");
		registerName.put(368, "f11");
		registerName.put(376, "f12");
		registerName.put(384, "f13");
		registerName.put(392, "f14");
		registerName.put(400, "f15");
		registerName.put(408, "f16");
		registerName.put(416, "f17");
		registerName.put(424, "f18");
		registerName.put(432, "f19");
		registerName.put(440, "f20");
		registerName.put(448, "f21");
		registerName.put(456, "f22");
		registerName.put(464, "f23");
		registerName.put(472, "f24");
		registerName.put(480, "f25");
		registerName.put(488, "f26");
		registerName.put(496, "f27");
		registerName.put(504, "f28");
		registerName.put(512, "f29");
		registerName.put(520, "f30");
		registerName.put(528, "f31");
		registerName.put(536, "fir");
		registerName.put(540, "fccr");
		registerName.put(544, "fexr");
		registerName.put(548, "fenr");
		registerName.put(552, "fcsr");
		registerName.put(560, "ulr");
		registerName.put(568, "emnote");
		registerName.put(576, "cmstart");
		registerName.put(584, "cmlen");
		registerName.put(592, "nraddr");
		registerName.put(600, "evc_failaddr");
		registerName.put(608, "evc_counter");
		registerName.put(612, "cond");
		registerName.put(616, "ip_at_syscall");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 528 && index >= 16) || (index == 256));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchMIPS64;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 256;
	}
}
