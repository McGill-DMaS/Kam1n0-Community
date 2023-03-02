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
package ca.mcgill.sis.dmas.kam1n0.vex;

import java.io.Serializable;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.Endianness;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.InstructionSize;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;

public class VexArchitecture implements Serializable {

	private static final long serialVersionUID = 3758497416220252013L;
	public VexArchitectureType type;
	public ArchitectureInfo info = new ArchitectureInfo();

	public static class VexCacheInfo implements Serializable {
		private static final long serialVersionUID = -4073129135107631078L;
		public int num_levels = 0;
		public int num_caches = 0;
		public boolean icaches_maintain_coherence = true;
	}

	public static class ArchitectureInfo implements Serializable {
		private static final long serialVersionUID = 308707382120013985L;
		public int hwcaps = 0;
		public VexEndnessType endness = VexEndnessType.VexEndnessLE;
		public VexCacheInfo cacheInfo = new VexCacheInfo();
		public int ppc_icache_line_szB = 0;
		public int ppc_dcbz_szB = 0;
		public int ppc_dcbzl_szB = 0;
		public int arm64_dMinLine_lg2_szB = 0;
		public int arm64_iMinLine_lg2_szB = 0;
		public int x86_cr0 = 0xffffffff;

		public static ArchitectureInfo createDefault() {
			return new ArchitectureInfo();
		}
	}

	public static VexArchitecture createArchitectureFromString(String str) {
		return new VexArchitecture();
	}

	/**
	 * did nothing more than simple translation at this moment;
	 * 
	 * @param architecture
	 * @return
	 */
	public static VexArchitecture convert(Architecture architecture) {
		VexArchitecture vex = new VexArchitecture();
		switch (architecture.type) {
		case metapc:
			if (architecture.size == InstructionSize.b32)
				vex.type = VexArchitectureType.VexArchX86;
			else
				vex.type = VexArchitectureType.VexArchAMD64;
			break;
		case arm:
			if (architecture.size == InstructionSize.b32)
				vex.type = VexArchitectureType.VexArchARM;
			else
				vex.type = VexArchitectureType.VexArchARM64;
			break;
		case ppc:
			if (architecture.size == InstructionSize.b32)
				vex.type = VexArchitectureType.VexArchPPC32;
			else
				vex.type = VexArchitectureType.VexArchPPC64;
			break;
		case mips:
			if (architecture.size == InstructionSize.b32)
				vex.type = VexArchitectureType.VexArchMIPS32;
			else
				vex.type = VexArchitectureType.VexArchMIPS64;
			break;
		default:
			break;
		}

		if (architecture.endian == Endianness.le)
			vex.info.endness = VexEndnessType.VexEndnessLE;
		else if (architecture.endian == Endianness.be)
			vex.info.endness = VexEndnessType.VexEndnessBE;
		else
			vex.info.endness = VexEndnessType.VexEndness_INVALID;

		return vex;
	}

}
