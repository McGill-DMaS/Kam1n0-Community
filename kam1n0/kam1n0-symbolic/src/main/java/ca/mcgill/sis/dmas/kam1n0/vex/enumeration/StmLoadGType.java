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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;

import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.*;

public enum StmLoadGType {
	ILGop_INVALID, ILGop_Ident64, /* 64 bit, no conversion */
	ILGop_Ident32, /* 32 bit, no conversion */
	ILGop_16Uto32, /* 16 bit load, Z-widen to 32 */
	ILGop_16Sto32, /* 16 bit load, S-widen to 32 */
	ILGop_8Uto32, /* 8 bit load, Z-widen to 32 */
	ILGop_8Sto32; /* 8 bit load, S-widen to 32 */

	private static Logger logger = LoggerFactory.getLogger(StmLoadGType.class);

	public static int startValue() {
		return 0x1D00;
	}

	public static StmLoadGType fromInteger(int index) {
		return VexEnumeration.retrieveType(index, StmLoadGType.class);
	}

	public boolean isZeroExtend() {
		return this.toString().contains("U");
	}

	public boolean isSignExtend() {
		return this.toString().contains("S");
	}

	@JsonIgnore
	public VexOperationType getTypeConversionOpr() {
		switch (this) {
		case ILGop_Ident64:
			return null;
		case ILGop_Ident32:
			return null;
		case ILGop_16Uto32:
			return VexOperationType.Iop_16Uto32;
		case ILGop_16Sto32:
			return VexOperationType.Iop_16Sto32;
		case ILGop_8Uto32:
			return VexOperationType.Iop_8Uto32;
		case ILGop_8Sto32:
			return VexOperationType.Iop_8Sto32;
		default:
			logger.error("Unsupported conversion for {}.", this);
			return null;
		}
	}

	public TypeInformation toTypeInformation() {
		TypeInformation valType = new TypeInformation();
		switch (this) {
		case ILGop_Ident64:
			valType.outputType = Ity_I64;
			valType.argType.add(Ity_I64);
			break;
		case ILGop_Ident32:
			valType.outputType = Ity_I32;
			valType.argType.add(Ity_I32);
			break;
		case ILGop_16Uto32:
		case ILGop_16Sto32:
			valType.outputType = Ity_I32;
			valType.argType.add(Ity_I16);
			break;
		case ILGop_8Uto32:
		case ILGop_8Sto32:
			valType.outputType = Ity_I32;
			valType.argType.add(Ity_I8);
			break;
		default:
			logger.error("Unsupported conversion for {}.", this);
			return null;
		}
		return valType;
	}

	public int[] getSize() {
		switch (this) {
		case ILGop_Ident64:
			return new int[] { 64, 64 };
		case ILGop_Ident32:
			return new int[] { 32, 32 };
		case ILGop_16Uto32:
			return new int[] { 16, 32 };
		case ILGop_16Sto32:
			return new int[] { 16, 32 };
		case ILGop_8Uto32:
			return new int[] { 8, 32 };
		case ILGop_8Sto32:
			return new int[] { 8, 32 };
		default:
			logger.error("Invild StmLoadGType {}", this);
			return null;
		}
	}
}