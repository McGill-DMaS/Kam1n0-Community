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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;

import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexConstantType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

public class VexConstant implements Serializable {

	private static final long serialVersionUID = -8039155006866986862L;
	private static Logger logger = LoggerFactory.getLogger(VexConstant.class);

	public String value;
	public VexConstantType type;
	public int size;

	public VexConstant() {

	}

	@JsonIgnore
	public long getVal() {
		// all constants are unsigned
		return Long.parseUnsignedLong(value, 16);
	}

	@JsonIgnore

	public static VexConstant createVexConstant(int vexTypeIndex, String hexString) {
		if (hexString.startsWith("0x") || hexString.startsWith("0X"))
			hexString = hexString.substring(2, hexString.length());
		VexConstantType type = VexEnumeration.retrieveType(vexTypeIndex, VexConstantType.class);
		return createVexConstant(type, hexString);
	}

	public static VexConstant createVexConstant(VexConstantType type, String hexString) {
		VexConstant constant = new VexConstant();
		constant.value = hexString;
		constant.type = type;
		constant.size = type.toVariableType().numOfBit();
		return constant;
	}

	public static VexConstant createVexConstantFromSize(int size, String hexString) {
		VexConstantType type;
		switch (size) {
		case 1:
			type = VexConstantType.Ico_U1;
			break;
		case 8:
			type = VexConstantType.Ico_U8;
			break;
		case 16:
			type = VexConstantType.Ico_U16;
			break;
		case 32:
			type = VexConstantType.Ico_U32;
			break;
		case 64:
			type = VexConstantType.Ico_U64;
			break;
		case 128:
			type = VexConstantType.Ico_V128;
			break;
		case 256:
			type = VexConstantType.Ico_V256;
			break;
		default:
			logger.error("looking for type of {} bits. nonexisted. Setting 32", size);
			type = VexConstantType.Ico_U32;
			break;
		}
		return createVexConstant(type, hexString);
	}

}
