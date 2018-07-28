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

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;

public abstract class Guest {

	public HashMap<Integer, String> registerName = new HashMap<>();
	private Map<String, Integer> registerNameRev = null;

	public Integer getRegOffset(String regName) {
		if (registerNameRev == null) {
			registerNameRev = registerName.entrySet().stream()
					.collect(Collectors.toMap(ent -> ent.getValue(), ent -> ent.getKey()));
		}
		return registerNameRev.get(regName);
	}

	public abstract VexArchitectureType getType();

	private static HashMap<VexArchitectureType, Guest> supportedGuests = new HashMap<>();
	static {
		supportedGuests.put(VexArchitectureType.VexArchX86, new GuestX86());
		supportedGuests.put(VexArchitectureType.VexArchAMD64, new GuestAMD64());
		supportedGuests.put(VexArchitectureType.VexArchARM, new GuestARM());
		supportedGuests.put(VexArchitectureType.VexArchARM64, new GuestARM64());
		supportedGuests.put(VexArchitectureType.VexArchMIPS32, new GuestMIPS32());
		supportedGuests.put(VexArchitectureType.VexArchMIPS64, new GuestMIPS64());
		supportedGuests.put(VexArchitectureType.VexArchPPC32, new GuestPPC32());
		supportedGuests.put(VexArchitectureType.VexArchS390X, new GuestS390X());
		supportedGuests.put(VexArchitectureType.VexArchTILEGX, new GuestTILEGX());
	}

	public static Guest getGuestInfo(VexArchitectureType type) {
		return supportedGuests.get(type);
	}

	public boolean isProgramCounter(ComputationNode node) {
		return node.isRegister() && this.isProgramCounter(node.index);
	}

	public boolean isGeneralReg(ComputationNode node) {
		return node.isRegister() && this.isGeneralReg(node.index);
	}

	public abstract boolean isProgramCounter(int offset);

	public abstract boolean isGeneralReg(int offset);
}
