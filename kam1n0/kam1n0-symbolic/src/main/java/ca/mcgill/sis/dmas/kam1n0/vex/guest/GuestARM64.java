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

public class GuestARM64 extends Guest {
	public GuestARM64() {
		registerName.put(16, "x0");
		registerName.put(24, "x1");
		registerName.put(32, "x2");
		registerName.put(40, "x3");
		registerName.put(48, "x4");
		registerName.put(56, "x5");
		registerName.put(64, "x6");
		registerName.put(72, "x7");
		registerName.put(80, "x8");
		registerName.put(88, "x9");
		registerName.put(96, "x10");
		registerName.put(104, "x11");
		registerName.put(112, "x12");
		registerName.put(120, "x13");
		registerName.put(128, "x14");
		registerName.put(136, "x15");
		registerName.put(144, "x16");
		registerName.put(152, "x17");
		registerName.put(160, "x18");
		registerName.put(168, "x19");
		registerName.put(176, "x20");
		registerName.put(184, "x21");
		registerName.put(192, "x22");
		registerName.put(200, "x23");
		registerName.put(208, "x24");
		registerName.put(216, "x25");
		registerName.put(224, "x26");
		registerName.put(232, "x27");
		registerName.put(240, "x28");
		registerName.put(248, "x29");
		registerName.put(256, "x30");
		registerName.put(264, "xsp");
		registerName.put(272, "pc");
		registerName.put(280, "cc_op");
		registerName.put(288, "cc_dep1");
		registerName.put(296, "cc_dep2");
		registerName.put(304, "cc_ndep");
		registerName.put(312, "tpidr_el0");
		registerName.put(320, "q0");
		registerName.put(336, "q1");
		registerName.put(352, "q2");
		registerName.put(368, "q3");
		registerName.put(384, "q4");
		registerName.put(400, "q5");
		registerName.put(416, "q6");
		registerName.put(432, "q7");
		registerName.put(448, "q8");
		registerName.put(464, "q9");
		registerName.put(480, "q10");
		registerName.put(496, "q11");
		registerName.put(512, "q12");
		registerName.put(528, "q13");
		registerName.put(544, "q14");
		registerName.put(560, "q15");
		registerName.put(576, "q16");
		registerName.put(592, "q17");
		registerName.put(608, "q18");
		registerName.put(624, "q19");
		registerName.put(640, "q20");
		registerName.put(656, "q21");
		registerName.put(672, "q22");
		registerName.put(688, "q23");
		registerName.put(704, "q24");
		registerName.put(720, "q25");
		registerName.put(736, "q26");
		registerName.put(752, "q27");
		registerName.put(768, "q28");
		registerName.put(784, "q29");
		registerName.put(800, "q30");
		registerName.put(816, "q31");
		registerName.put(832, "qcflag");
		registerName.put(848, "emnote");
		registerName.put(852, "cmstart");
		registerName.put(860, "cmlen");
		registerName.put(868, "nraddr");
		registerName.put(876, "ip_at_syscall");
		registerName.put(884, "fpcr");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 136 && index >= 16) || (index <= 816 && index >= 320) || (index == 272));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchARM64;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 272;
	}

}
