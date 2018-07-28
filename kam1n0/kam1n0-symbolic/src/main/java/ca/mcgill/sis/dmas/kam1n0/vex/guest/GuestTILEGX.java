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

public class GuestTILEGX extends Guest {
	public GuestTILEGX() {
		registerName.put(0, "r0");
		registerName.put(8, "r1");
		registerName.put(16, "r2");
		registerName.put(24, "r3");
		registerName.put(32, "r4");
		registerName.put(40, "r5");
		registerName.put(48, "r6");
		registerName.put(56, "r7");
		registerName.put(64, "r8");
		registerName.put(72, "r9");
		registerName.put(80, "r10");
		registerName.put(88, "r11");
		registerName.put(96, "r12");
		registerName.put(104, "r13");
		registerName.put(112, "r14");
		registerName.put(120, "r15");
		registerName.put(128, "r16");
		registerName.put(136, "r17");
		registerName.put(144, "r18");
		registerName.put(152, "r19");
		registerName.put(160, "r20");
		registerName.put(168, "r21");
		registerName.put(176, "r22");
		registerName.put(184, "r23");
		registerName.put(192, "r24");
		registerName.put(200, "r25");
		registerName.put(208, "r26");
		registerName.put(216, "r27");
		registerName.put(224, "r28");
		registerName.put(232, "r29");
		registerName.put(240, "r30");
		registerName.put(248, "r31");
		registerName.put(256, "r32");
		registerName.put(264, "r33");
		registerName.put(272, "r34");
		registerName.put(280, "r35");
		registerName.put(288, "r36");
		registerName.put(296, "r37");
		registerName.put(304, "r38");
		registerName.put(312, "r39");
		registerName.put(320, "r40");
		registerName.put(328, "r41");
		registerName.put(336, "r42");
		registerName.put(344, "r43");
		registerName.put(352, "r44");
		registerName.put(360, "r45");
		registerName.put(368, "r46");
		registerName.put(376, "r47");
		registerName.put(384, "r48");
		registerName.put(392, "r49");
		registerName.put(400, "r50");
		registerName.put(408, "r51");
		registerName.put(416, "r52");
		registerName.put(424, "r53");
		registerName.put(432, "r54");
		registerName.put(440, "r55");
		registerName.put(448, "r56");
		registerName.put(456, "r57");
		registerName.put(464, "r58");
		registerName.put(472, "r59");
		registerName.put(480, "r60");
		registerName.put(488, "r61");
		registerName.put(496, "r62");
		registerName.put(504, "r63");
		registerName.put(512, "pc");
		registerName.put(520, "spare");
		registerName.put(528, "EMNOTE");
		registerName.put(536, "CMSTART");
		registerName.put(544, "CMLEN");
		registerName.put(552, "NRADDR");
		registerName.put(560, "cmpexch");
		registerName.put(568, "zero");
		registerName.put(576, "ex_context_0");
		registerName.put(584, "ex_context_1");
		registerName.put(592, " host_EvC_FAILADDR");
		registerName.put(600, " host_EvC_COUNTER");
		registerName.put(608, "COND");
		registerName.put(616, " PAD");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 512 && index >= 0) || (index == 184));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchTILEGX;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 512;
	}
}
