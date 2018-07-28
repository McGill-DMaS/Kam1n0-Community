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
package ca.mcgill.sis.dmas.kam1n0.vex.operation;

import java.util.Arrays;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.Attribute;

public class VexConstantSimplifier {

	public static interface VexOperationInJava {
		public String calculate(Attribute att, String... args);
	}

	public static HashMap<String, VexOperationInJava> map = new HashMap<>();

	public static HashMap<String, VexOperationInJava> mergeMap = new HashMap<>();

	static {
		map.put("Xor", VexConstantSimplifier::Xor);
		map.put("Or", VexConstantSimplifier::Or);
		map.put("And", VexConstantSimplifier::And);
		map.put("Not", VexConstantSimplifier::Not);
		map.put("Add", VexConstantSimplifier::Add);
		map.put("Sub", VexConstantSimplifier::Sub);
		map.put("Mul", VexConstantSimplifier::Mul);
		map.put("Div", VexConstantSimplifier::Div);

		map.put("ShlN", VexConstantSimplifier::Shl);
		map.put("Shl", VexConstantSimplifier::Shl);
		map.put("ShrN", VexConstantSimplifier::Shr);
		map.put("Shr", VexConstantSimplifier::Shr);
		map.put("SarN", VexConstantSimplifier::Sar);
		map.put("Sar", VexConstantSimplifier::Sar);

		map.put("CmpEQ", VexConstantSimplifier::CmpEQ);
		map.put("CmpNE", VexConstantSimplifier::CmpNE);
		map.put("CmpGT", VexConstantSimplifier::CmpGT);
		map.put("CmpLT", VexConstantSimplifier::CmpLT);
		map.put("CmpLE", VexConstantSimplifier::CmpLE);
		map.put("CmpORD", VexConstantSimplifier::CmpORD);
	}

	public static void main(String[] args) {
		{
			int val = -1;
			String valstr = Integer.toHexString(val);
			Long vallong = Long.parseUnsignedLong(valstr, 16);
			System.out.println(valstr);
			System.out.println(Long.toHexString(vallong));
		}
		{
			Attribute att = new Attribute();
			int val = 128;
			att._from_size = 8;
			System.out.println(Integer.toHexString(val));
			System.out.println(ExtendUnsigned(Integer.toUnsignedString(val, 16)));
		}
		{
			Attribute att = new Attribute();
			int val = 128;
			att._from_size = 16;
			System.out.println(Integer.toHexString(val));
			System.out.println(ExtendSigned(Integer.toUnsignedString(val, 16)));
		}
		{
			Attribute att = new Attribute();
			att._from_size = 32;
			System.out.println(Or(att, Long.toUnsignedString(0x2, 16), Long.toUnsignedString(0xc0, 16)));
		}
		{
			int val1 = -1;
			String valHex = Integer.toHexString(val1);
			Attribute att = new Attribute();
			att._from_size = 64;
			String valExtended = ExtendSigned(valHex);
			System.out.println(val1);
			System.out.println(Long.parseUnsignedLong(valExtended, 16));
		}
		{
			int val1 = -3;
			String valHex = Integer.toHexString(val1);
			System.out.println(valHex);
			String valLongHex = ExtendSigned(valHex);
			System.out.println(valLongHex);
			System.out.println(Long.parseUnsignedLong(valLongHex, 16));
		}
	}

	private static Logger logger = LoggerFactory.getLogger(VexConstantSimplifier.class);

	public static String CP(Attribute attr, String... values) {
		if (values.length != 1) {
			logger.error("Not takes only one argument but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		return values[0];
	}

	public static String ExtendUnsigned(String value) {
		long val = Long.parseUnsignedLong(value, 16);
		return Long.toHexString(val);
	}

	public static String ExtendSigned(String value) {
		// one's complement
		long val = Long.parseUnsignedLong(value, 16);
		String bits = Long.toBinaryString(val);
		long maks = -1l << bits.length();
		if (bits.startsWith("1"))
			val |= maks;
		return Long.toHexString(val);
	}

	public static String Xor(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Xor takes only two argument but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) ^ Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String Or(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Or takes only two argument but {} given: {}. Will process the first one only.", values.length,
					Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) | Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String And(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("And takes only two argument but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) & Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String Not(Attribute attr, String... values) {
		if (values.length != 1) {
			logger.error("Not takes only one argument but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		long val = ~Long.parseUnsignedLong(v1, 16);
		return Long.toHexString(val);
	}

	public static String Add(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Add takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) + Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String Sub(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Sub takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) - Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String Mul(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("MulUnsigned takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) * Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String Div(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Div takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		if (attr.isSigned()) {
			String v1 = ExtendUnsigned(values[0]);
			String v2 = ExtendUnsigned(values[1]);
			long val = Long.parseUnsignedLong(v1, 16) / Long.parseUnsignedLong(v2, 16);
			return Long.toHexString(val);
		} else {
			String v1 = ExtendSigned(values[0]);
			String v2 = ExtendSigned(values[1]);
			long val = Long.parseUnsignedLong(v1, 16) / Long.parseUnsignedLong(v2, 16);
			return Long.toHexString(val);
		}
	}

	public static String Shl(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Add takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) << Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	/**
	 * Corresponding to mkBVLSHR. Logical shift right.
	 * 
	 * @param attr
	 * @param values
	 * @return
	 */
	public static String Shr(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Add takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) >>> Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	/**
	 * Corresponding to mkBVASHR. Arithmetic shift right.
	 * 
	 * @param attr
	 * @param values
	 * @return
	 */
	public static String Sar(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("Add takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		long val = Long.parseUnsignedLong(v1, 16) >> Long.parseUnsignedLong(v2, 16);
		return Long.toHexString(val);
	}

	public static String CmpEQ(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CmpEQ takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		boolean val = Long.parseUnsignedLong(v1, 16) == Long.parseUnsignedLong(v2, 16);
		if (val)
			return "01";
		else
			return "00";
	}

	public static String CmpNE(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CmpNE takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		String v1 = ExtendUnsigned(values[0]);
		String v2 = ExtendUnsigned(values[1]);
		boolean val = Long.parseUnsignedLong(v1, 16) != Long.parseUnsignedLong(v2, 16);
		if (val)
			return "01";
		else
			return "00";
	}

	public static String CmpGT(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CMPGT takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		if (!attr.isSigned()) {
			String v1 = ExtendUnsigned(values[0]);
			String v2 = ExtendUnsigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) > Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		} else {
			String v1 = ExtendSigned(values[0]);
			String v2 = ExtendSigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) > Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		}
	}

	public static String CmpGE(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CmpGE takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		if (attr.isSigned()) {
			String v1 = ExtendUnsigned(values[0]);
			String v2 = ExtendUnsigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) >= Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		} else {
			String v1 = ExtendSigned(values[0]);
			String v2 = ExtendSigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) >= Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		}
	}

	public static String CmpLT(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CmpLT takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}
		if (attr.isSigned()) {
			String v1 = ExtendUnsigned(values[0]);
			String v2 = ExtendUnsigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) < Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		} else {
			String v1 = ExtendSigned(values[0]);
			String v2 = ExtendSigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) < Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		}
	}

	public static String CmpLE(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CmpLT takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}

		if (attr.isSigned()) {
			String v1 = ExtendUnsigned(values[0]);
			String v2 = ExtendUnsigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) <= Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		} else {
			String v1 = ExtendSigned(values[0]);
			String v2 = ExtendSigned(values[1]);
			boolean val = Long.parseUnsignedLong(v1, 16) <= Long.parseUnsignedLong(v2, 16);
			if (val)
				return "01";
			else
				return "00";
		}
	}

	public static String CmpORD(Attribute attr, String... values) {
		if (values.length != 2) {
			logger.error("CmpLT takes only two arguments but {} given: {}. Will process the first one only.",
					values.length, Arrays.toString(values));
			return null;
		}

		String v1;
		String v2;
		if (attr.isSigned()) {
			v1 = ExtendUnsigned(values[0]);
			v2 = ExtendUnsigned(values[1]);
		} else {
			v1 = ExtendSigned(values[0]);
			v2 = ExtendSigned(values[1]);
		}
		long v1l = Long.parseUnsignedLong(v1, 16);
		long v2l = Long.parseUnsignedLong(v2, 16);
		if (v1l == v2l)
			return "02";
		else if (v1l < v2l)
			return "08";
		else
			return "04";
	}

}
