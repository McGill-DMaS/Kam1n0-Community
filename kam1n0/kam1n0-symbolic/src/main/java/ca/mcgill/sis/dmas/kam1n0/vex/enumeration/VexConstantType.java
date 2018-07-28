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

import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_F32;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_F64;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_I1;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_I16;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_I32;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_I64;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_I8;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_V128;
import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.Ity_V256;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;

public enum VexConstantType {

	Ico_U1, Ico_U8, Ico_U16, Ico_U32, Ico_U64, Ico_F32, /*
														 * 32-bit IEEE754
														 * floating
														 */
	Ico_F32i, /*
				 * 32-bit unsigned int to be interpreted literally as a IEEE754
				 * single value.
				 */
	Ico_F64, /* 64-bit IEEE754 floating */
	Ico_F64i, /*
				 * 64-bit unsigned int to be interpreted literally as a IEEE754
				 * double value.
				 */
	Ico_V128, /*
				 * 128-bit restricted vector constant, with 1 bit (repeated 8
				 * times) for each of the 16 x 1-byte lanes
				 */
	Ico_V256; /*
				 * 256-bit restricted vector constant, with 1 bit (repeated 8
				 * times) for each of the 32 x 1-byte lanes
				 */

	private static Logger logger = LoggerFactory.getLogger(VexConstantType.class);

	public static int startValue() {
		return 0x1300;
	}

	public static VexConstantType fromInteger(int index) {
		return VexEnumeration.retrieveType(index, VexConstantType.class);
	}

	public VexVariableType toVariableType() {
		switch (this) {
		case Ico_U1:
			return Ity_I1;
		case Ico_U8:
			return Ity_I8;
		case Ico_U16:
			return Ity_I16;
		case Ico_U32:
			return Ity_I32;
		case Ico_U64:
			return Ity_I64;
		case Ico_F32:
			return Ity_F32;
		case Ico_F32i:
			return Ity_F32;
		case Ico_F64:
			return Ity_F64;
		case Ico_F64i:
			return Ity_F64;
		case Ico_V128:
			return Ity_V128;
		case Ico_V256:
			return Ity_V256;
		default:
			logger.error("Unsupported vex constant type {} for conversion.", this);
			return null;
		}
	}

}