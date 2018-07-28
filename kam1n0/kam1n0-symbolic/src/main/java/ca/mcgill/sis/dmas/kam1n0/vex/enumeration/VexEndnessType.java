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

import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;

public enum VexEndnessType {

	VexEndness_INVALID, /* unknown endianness */
	VexEndnessLE, /* little endian */
	VexEndnessBE /* big endian */;

	public static int startValue() {
		return 0x600;
	}

	public static VexEndnessType fromInteger(int index) {
		// IREndness compatibility:
		if (index == 0x1200)
			index = 0x601;
		else if (index == 0x1201)
			index = 0x602;

		VexEndnessType type = VexEnumeration.retrieveType(index, VexEndnessType.class);
		if (type == null) {
			return VexEndnessBE;
		} else
			return type;
	}
}