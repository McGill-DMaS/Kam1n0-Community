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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;

public enum VexVariableType {

	Ity_INVALID, //
	Ity_I1, //
	Ity_I8, //
	Ity_I16, //
	Ity_I32, //
	Ity_I64, //
	Ity_I128, /* 128-bit scalar */
	Ity_F16, /* 16 bit float */
	Ity_F32, /* IEEE 754 float */
	Ity_F64, /* IEEE 754 double */
	Ity_D32, /* 32-bit Decimal floating point */
	Ity_D64, /* 64-bit Decimal floating point */
	Ity_D128, /* 128-bit Decimal floating point */
	Ity_F128, /* 128-bit floating point; implementation defined */
	Ity_V128, /* 128-bit SIMD */
	Ity_V256, /* 256-bit SIMD */

	// ADDED NEW TYPES FOR CCALLS.
	Ity_I2, Ity_I3, Ity_I4, Ity_I5, Ity_I6, Ity_I7, Ity_I9, Ity_I10, Ity_I11, Ity_I12, Ity_I13, Ity_I14, Ity_I15, Ity_I17, Ity_I18, Ity_I19, Ity_I20, Ity_I21, Ity_I22, Ity_I23, Ity_I24, Ity_I25, Ity_I26, Ity_I27, Ity_I28, Ity_I29, Ity_I30, Ity_I31, Ity_I33, Ity_I34, Ity_I35, Ity_I36, Ity_I37, Ity_I38, Ity_I39, Ity_I40, Ity_I41, Ity_I42, Ity_I43, Ity_I44, Ity_I45, Ity_I46, Ity_I47, Ity_I48, Ity_I49, Ity_I50, Ity_I51, Ity_I52, Ity_I53, Ity_I54, Ity_I55, Ity_I56, Ity_I57, Ity_I58, Ity_I59, Ity_I60, Ity_I61, Ity_I62, Ity_I63, Ity_I65, Ity_I66, Ity_I67, Ity_I68, Ity_I69, Ity_I70, Ity_I71, Ity_I72, Ity_I73, Ity_I74, Ity_I75, Ity_I76, Ity_I77, Ity_I78, Ity_I79, Ity_I80, Ity_I81, Ity_I82, Ity_I83, Ity_I84, Ity_I85, Ity_I86, Ity_I87, Ity_I88, Ity_I89, Ity_I90, Ity_I91, Ity_I92, Ity_I93, Ity_I94, Ity_I95, Ity_I96, Ity_I97, Ity_I98, Ity_I99, Ity_I100, Ity_I101, Ity_I102, Ity_I103, Ity_I104, Ity_I105, Ity_I106, Ity_I107, Ity_I108, Ity_I109, Ity_I110, Ity_I111, Ity_I112, Ity_I113, Ity_I114, Ity_I115, Ity_I116, Ity_I117, Ity_I118, Ity_I119, Ity_I120, Ity_I121, Ity_I122, Ity_I123, Ity_I124, Ity_I125, Ity_I126, Ity_I127;

	public static int startValue() {
		return 0x1100;
	}

	public String shortString() {
		return this.toString().replace("Ity_", "");
	}

	public boolean isI() {
		return shortString().contains("I");
	}

	public boolean isF() {
		return shortString().contains("F");
	}

	public boolean isD() {
		return shortString().contains("D");
	}

	public boolean isV() {
		return shortString().contains("V");
	}

	private static Logger logger = LoggerFactory.getLogger(VexVariableType.class);

	public static VexVariableType getIntType(int bits) {
		// switch (bits) {
		// case 1:
		// return Ity_I1;
		// case 8:
		// return Ity_I8;
		// case 16:
		// return Ity_I16;
		// case 32:
		// return Ity_I32;
		// case 64:
		// return Ity_I64;
		// case 128:
		// return Ity_I128;
		// default:
		// logger.error("Unknown type for {} bits.", bits);
		// return Ity_I32;
		// }
		VexVariableType val = null;
		try {
			val = VexVariableType.valueOf("Ity_I" + bits);;
		} catch (Exception e) {
			logger.info("Invalid type for {} bits", bits);
		}
		return val;
	}

	public static VexVariableType getFltType(int bits) {
		switch (bits) {
		case 16:
			return Ity_F16;
		case 32:
			return Ity_F32;
		case 64:
			return Ity_F64;
		default:
			logger.error("Unknown type for {} bits. returning {}", bits, Ity_F32);
			return Ity_F32;
		}
	}

	private static Pattern p = Pattern.compile("\\d+");

	public int numOfBit() {

		if (this.equals(Ity_INVALID))
			return -1;

		Matcher mat = p.matcher(this.toString());
		if (mat.find()) {
			Integer val = Integer.parseInt(mat.group());
			return val;
		} else
			return -1;

		// switch (this) {
		// case Ity_INVALID:
		// return -1;
		// case //
		// Ity_I1:
		// return 1;
		// case //
		// Ity_I8:
		// return 8;
		// case //
		// Ity_I16:
		// return 16;
		// case //
		// Ity_I32:
		// return 32;
		// case //
		// Ity_I64:
		// return 64;
		// case //
		// Ity_I128:
		// return 128;
		// case /* 128-bit scalar */
		// Ity_F16:
		// return 16;
		// case /* 16 bit float */
		// Ity_F32:
		// return 32;
		// case /* IEEE 754 float */
		// Ity_F64:
		// return 64;
		// case /* IEEE 754 double */
		// Ity_D32:
		// return 32;
		// case /* 32-bit Decimal floating point */
		// Ity_D64:
		// return 64;
		// case /* 64-bit Decimal floating point */
		// Ity_D128:
		// return 128;
		// case /* 128-bit Decimal floating point */
		// Ity_F128:
		// return 128;
		// case /* 128-bit floating point; implementation defined */
		// Ity_V128:
		// return 128;
		// case /* 128-bit SIMD */
		// Ity_V256:
		// return 256; /* 256-bit SIMD */
		// default:
		// return -1;
		// }
	}

	public static VexVariableType fromInteger(int index) {
		return VexEnumeration.retrieveType(index, VexVariableType.class);
	}

}
