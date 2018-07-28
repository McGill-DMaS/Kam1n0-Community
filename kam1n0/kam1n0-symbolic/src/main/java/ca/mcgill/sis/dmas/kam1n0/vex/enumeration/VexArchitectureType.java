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
package ca.mcgill.sis.dmas.kam1n0.vex.enumeration;

import com.fasterxml.jackson.annotation.JsonIgnore;

import ca.mcgill.sis.dmas.kam1n0.vex.guest.Guest;
import ca.mcgill.sis.dmas.kam1n0.vex.guest.GuestARM64;
import ca.mcgill.sis.dmas.kam1n0.vex.guest.GuestX86;

public enum VexArchitectureType {
	VexArch_INVALID, //
	VexArchX86, //
	VexArchAMD64, //
	VexArchARM, //
	VexArchARM64, //
	VexArchPPC32, //
	VexArchPPC64, //
	VexArchS390X, //
	VexArchMIPS32, //
	VexArchMIPS64, //
	VexArchTILEGX//
	;

	public static int startValue() {
		return 0x400;
	}

	public VexVariableType defaultTypte() {
		return VexVariableType.valueOf("Ity_I" + this.size());
	}
	
	@JsonIgnore
	public Guest getGuestInfo(){
		return Guest.getGuestInfo(this);
	}


	public int size() {
		String str = this.toString();
		if (str.contains("32"))
			return 32;
		if (str.contains("64"))
			return 64;
		if (str.contains("86"))
			return 32;
		return 32;
	}

}