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

public class GuestPPC64 extends Guest {
	public GuestPPC64() {
		registerName.put(0, "host_evc_failaddr");
		registerName.put(8, "host_evc_counter");
		registerName.put(12, "pad0");
		registerName.put(16, "r0");
		registerName.put(24, "r1");
		registerName.put(32, "r2");
		registerName.put(40, "r3");
		registerName.put(48, "r4");
		registerName.put(56, "r5");
		registerName.put(64, "r6");
		registerName.put(72, "r7");
		registerName.put(80, "r8");
		registerName.put(88, "r9");
		registerName.put(96, "r10");
		registerName.put(104, "r11");
		registerName.put(112, "r12");
		registerName.put(120, "r13");
		registerName.put(128, "r14");
		registerName.put(136, "r15");
		registerName.put(144, "r16");
		registerName.put(152, "r17");
		registerName.put(160, "r18");
		registerName.put(168, "r19");
		registerName.put(176, "r20");
		registerName.put(184, "r21");
		registerName.put(192, "r22");
		registerName.put(200, "r23");
		registerName.put(208, "r24");
		registerName.put(216, "r25");
		registerName.put(224, "r26");
		registerName.put(232, "r27");
		registerName.put(240, "r28");
		registerName.put(248, "r29");
		registerName.put(256, "r30");
		registerName.put(264, "r31");
		registerName.put(272, "v0");
		registerName.put(288, "v1");
		registerName.put(304, "v2");
		registerName.put(320, "v3");
		registerName.put(336, "v4");
		registerName.put(352, "v5");
		registerName.put(368, "v6");
		registerName.put(384, "v7");
		registerName.put(400, "v8");
		registerName.put(416, "v9");
		registerName.put(432, "v10");
		registerName.put(448, "v11");
		registerName.put(464, "v12");
		registerName.put(480, "v13");
		registerName.put(496, "v14");
		registerName.put(512, "v15");
		registerName.put(528, "v16");
		registerName.put(544, "v17");
		registerName.put(560, "v18");
		registerName.put(576, "v19");
		registerName.put(592, "v20");
		registerName.put(608, "v21");
		registerName.put(624, "v22");
		registerName.put(640, "v23");
		registerName.put(656, "v24");
		registerName.put(672, "v25");
		registerName.put(688, "v26");
		registerName.put(704, "v27");
		registerName.put(720, "v28");
		registerName.put(736, "v29");
		registerName.put(752, "v30");
		registerName.put(768, "v31");
		registerName.put(784, "v32");
		registerName.put(800, "v33");
		registerName.put(816, "v34");
		registerName.put(832, "v35");
		registerName.put(848, "v36");
		registerName.put(864, "v37");
		registerName.put(880, "v38");
		registerName.put(896, "v39");
		registerName.put(912, "v40");
		registerName.put(928, "v41");
		registerName.put(944, "v42");
		registerName.put(960, "v43");
		registerName.put(976, "v44");
		registerName.put(992, "v45");
		registerName.put(1008, "v46");
		registerName.put(1024, "v47");
		registerName.put(1040, "v48");
		registerName.put(1056, "v49");
		registerName.put(1072, "v50");
		registerName.put(1088, "v51");
		registerName.put(1104, "v52");
		registerName.put(1120, "v53");
		registerName.put(1136, "v54");
		registerName.put(1152, "v55");
		registerName.put(1168, "v56");
		registerName.put(1184, "v57");
		registerName.put(1200, "v58");
		registerName.put(1216, "v59");
		registerName.put(1232, "v60");
		registerName.put(1248, "v61");
		registerName.put(1264, "v62");
		registerName.put(1280, "v63");
		registerName.put(1296, "pc");
		registerName.put(1304, "lr");
		registerName.put(1312, "ctr");
		registerName.put(1320, "xer_so");
		registerName.put(1321, "xer_ov");
		registerName.put(1322, "xer_ca");
		registerName.put(1323, "xer_bc");
		registerName.put(1324, "cr0_321");
		registerName.put(1325, "cr0_0");
		registerName.put(1326, "cr1_321");
		registerName.put(1327, "cr1_0");
		registerName.put(1328, "cr2_321");
		registerName.put(1329, "cr2_0");
		registerName.put(1330, "cr3_321");
		registerName.put(1331, "cr3_0");
		registerName.put(1332, "cr4_321");
		registerName.put(1333, "cr4_0");
		registerName.put(1334, "cr5_321");
		registerName.put(1335, "cr5_0");
		registerName.put(1336, "cr6_321");
		registerName.put(1337, "cr6_0");
		registerName.put(1338, "cr7_321");
		registerName.put(1339, "cr7_0");
		registerName.put(1340, "fpround");
		registerName.put(1341, "dfpround");
		registerName.put(1342, "pad1");
		registerName.put(1343, "pad2");
		registerName.put(1344, "vrsave");
		registerName.put(1348, "vscr");
		registerName.put(1352, "emnote");
		registerName.put(1356, "padding");
		registerName.put(1360, "cmstart");
		registerName.put(1368, "cmlen");
		registerName.put(1376, "nraddr");
		registerName.put(1384, "nraddr_gpr2");
		registerName.put(1392, "redir_sp");
		registerName.put(1400, "redir_stack");
		registerName.put(1656, "ip_at_syscall");
		registerName.put(1664, "sprg3_ro");
		registerName.put(1672, "tfhar");
		registerName.put(1680, "texasr");
		registerName.put(1688, "tfiar");
		registerName.put(1696, "texasru");
		registerName.put(1700, "padding1");
		registerName.put(1704, "padding2");
		registerName.put(1708, "padding3");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 296 && index >= 16) || (index == 1296));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchPPC64;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 1296;
	}
}
