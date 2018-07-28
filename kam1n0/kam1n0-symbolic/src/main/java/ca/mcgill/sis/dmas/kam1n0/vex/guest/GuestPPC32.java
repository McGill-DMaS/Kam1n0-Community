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

public class GuestPPC32 extends Guest {
	public GuestPPC32() {
		registerName.put(0, "host_evc_failaddr");
		registerName.put(4, "host_evc_counter");
		registerName.put(8, "pad3");
		registerName.put(12, "pad4");
		registerName.put(16, "r0");
		registerName.put(20, "r1");
		registerName.put(24, "r2");
		registerName.put(28, "r3");
		registerName.put(32, "r4");
		registerName.put(36, "r5");
		registerName.put(40, "r6");
		registerName.put(44, "r7");
		registerName.put(48, "r8");
		registerName.put(52, "r9");
		registerName.put(56, "r10");
		registerName.put(60, "r11");
		registerName.put(64, "r12");
		registerName.put(68, "r13");
		registerName.put(72, "r14");
		registerName.put(76, "r15");
		registerName.put(80, "r16");
		registerName.put(84, "r17");
		registerName.put(88, "r18");
		registerName.put(92, "r19");
		registerName.put(96, "r20");
		registerName.put(100, "r21");
		registerName.put(104, "r22");
		registerName.put(108, "r23");
		registerName.put(112, "r24");
		registerName.put(116, "r25");
		registerName.put(120, "r26");
		registerName.put(124, "r27");
		registerName.put(128, "r28");
		registerName.put(132, "r29");
		registerName.put(136, "r30");
		registerName.put(140, "r31");
		registerName.put(144, "v0");
		registerName.put(160, "v1");
		registerName.put(176, "v2");
		registerName.put(192, "v3");
		registerName.put(208, "v4");
		registerName.put(224, "v5");
		registerName.put(240, "v6");
		registerName.put(256, "v7");
		registerName.put(272, "v8");
		registerName.put(288, "v9");
		registerName.put(304, "v10");
		registerName.put(320, "v11");
		registerName.put(336, "v12");
		registerName.put(352, "v13");
		registerName.put(368, "v14");
		registerName.put(384, "v15");
		registerName.put(400, "v16");
		registerName.put(416, "v17");
		registerName.put(432, "v18");
		registerName.put(448, "v19");
		registerName.put(464, "v20");
		registerName.put(480, "v21");
		registerName.put(496, "v22");
		registerName.put(512, "v23");
		registerName.put(528, "v24");
		registerName.put(544, "v25");
		registerName.put(560, "v26");
		registerName.put(576, "v27");
		registerName.put(592, "v28");
		registerName.put(608, "v29");
		registerName.put(624, "v30");
		registerName.put(640, "v31");
		registerName.put(656, "v32");
		registerName.put(672, "v33");
		registerName.put(688, "v34");
		registerName.put(704, "v35");
		registerName.put(720, "v36");
		registerName.put(736, "v37");
		registerName.put(752, "v38");
		registerName.put(768, "v39");
		registerName.put(784, "v40");
		registerName.put(800, "v41");
		registerName.put(816, "v42");
		registerName.put(832, "v43");
		registerName.put(848, "v44");
		registerName.put(864, "v45");
		registerName.put(880, "v46");
		registerName.put(896, "v47");
		registerName.put(912, "v48");
		registerName.put(928, "v49");
		registerName.put(944, "v50");
		registerName.put(960, "v51");
		registerName.put(976, "v52");
		registerName.put(992, "v53");
		registerName.put(1008, "v54");
		registerName.put(1024, "v55");
		registerName.put(1040, "v56");
		registerName.put(1056, "v57");
		registerName.put(1072, "v58");
		registerName.put(1088, "v59");
		registerName.put(1104, "v60");
		registerName.put(1120, "v61");
		registerName.put(1136, "v62");
		registerName.put(1152, "v63");
		registerName.put(1168, "pc");
		registerName.put(1172, "lr");
		registerName.put(1176, "ctr");
		registerName.put(1180, "xer_so");
		registerName.put(1181, "xer_ov");
		registerName.put(1182, "xer_ca");
		registerName.put(1183, "xer_bc");
		registerName.put(1184, "cr0_321");
		registerName.put(1185, "cr0_0");
		registerName.put(1186, "cr1_321");
		registerName.put(1187, "cr1_0");
		registerName.put(1188, "cr2_321");
		registerName.put(1189, "cr2_0");
		registerName.put(1190, "cr3_321");
		registerName.put(1191, "cr3_0");
		registerName.put(1192, "cr4_321");
		registerName.put(1193, "cr4_0");
		registerName.put(1194, "cr5_321");
		registerName.put(1195, "cr5_0");
		registerName.put(1196, "cr6_321");
		registerName.put(1197, "cr6_0");
		registerName.put(1198, "cr7_321");
		registerName.put(1199, "cr7_0");
		registerName.put(1200, "fpround");
		registerName.put(1201, "dfpround");
		registerName.put(1202, "pad1");
		registerName.put(1203, "pad2");
		registerName.put(1204, "vrsave");
		registerName.put(1208, "vscr");
		registerName.put(1212, "emnote");
		registerName.put(1216, "cmstart");
		registerName.put(1220, "cmlen");
		registerName.put(1224, "nraddr");
		registerName.put(1228, "nraddr_gpr2");
		registerName.put(1232, "redir_sp");
		registerName.put(1236, "redir_stack");
		registerName.put(1364, "ip_at_syscall");
		registerName.put(1368, "sprg3_ro");
		registerName.put(1372, "padding1");
		registerName.put(1376, "tfhar");
		registerName.put(1384, "texasr");
		registerName.put(1392, "tfiar");
		registerName.put(1400, "texasru");
		registerName.put(1404, "padding2");
	}

	@Override
	public boolean isGeneralReg(int index) {
		return ((index <= 1168 && index >= 16) || (index == 1168));
	}

	@Override
	public VexArchitectureType getType() {
		return VexArchitectureType.VexArchPPC32;
	}

	@Override
	public boolean isProgramCounter(int index) {
		return index == 1168;
	}
}
