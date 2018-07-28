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
package ca.mcgill.sis.dmas.env;

import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.Random;

import org.apache.logging.log4j.message.ParameterizedMessage;

import com.google.common.base.Joiner;

public class StringResources {

	public final static String STR_LINEBREAK = System.getProperty("line.separator");
	public final static String STR_TOKENBREAK = " ";
	public final static String STR_PARAGRAPHBREAK = "# # # #";
	public final static String STR_EMPTY = "";
	public final static Joiner JOINER_TOKEN = Joiner.on(STR_TOKENBREAK).skipNulls();
	public final static Joiner JOINER_TOKEN_DOT = Joiner.on(".").skipNulls();
	public final static Joiner JOINER_TOKEN_CSV = Joiner.on(",").skipNulls();
	public final static Joiner JOINER_TOKEN_CSV_SPACE = Joiner.on(", ").skipNulls();
	public final static Joiner JOINER_TOKEN_AND_SPACE = Joiner.on(" & ").skipNulls();
	public final static Joiner JOINER_TOKEN_ANDC_SPACE = Joiner.on(" AND ").skipNulls();
	public final static Joiner JOINER_TOKEN_SCORE = Joiner.on("_").skipNulls();
	public final static Joiner JOINER_DASH = Joiner.on("-").skipNulls();
	public final static Joiner JOINER_NONE = Joiner.on("").skipNulls();
	public final static Joiner JOINER_LINE = Joiner.on(STR_LINEBREAK).skipNulls();

	public static String REGEX_URL = "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
	public static String REGEX_NON_ASCII = "[^\\x00-\\x7F]";
	public static String REGEX_NUMBER = ".*\\D.*";
	public static String REGEX_ANY = ".*";
	public static String REGEX_NOTHING = "a^";

	public static DecimalFormat FORMAT_AR2D = new DecimalFormat("#.00");
	public static DecimalFormat FORMAT_AR3D = new DecimalFormat("#.000");
	public static DecimalFormat FORMAT_AR4D = new DecimalFormat("#.0000");
	public static DecimalFormat FORMAT_AR5D = new DecimalFormat("#.00000");
	public static DecimalFormat FORMAT_2R2D = new DecimalFormat("00.00");
	public static DecimalFormat FORMAT_2R3D = new DecimalFormat("00.000");
	public static DecimalFormat FORMAT_2R4D = new DecimalFormat("00.0000");
	public static DecimalFormat FORMAT_3R3D = new DecimalFormat("000.000");
	public static DecimalFormat FORMAT_4R4D = new DecimalFormat("0000.0000");
	public static DecimalFormat FORMAT_5R5D = new DecimalFormat("00000.00000");
	public static DecimalFormat FORMAT_2R = new DecimalFormat("00");
	public static DecimalFormat FORMAT_3R = new DecimalFormat("000");
	public static DecimalFormat FORMAT_4R = new DecimalFormat("0000");
	public static DecimalFormat FORMAT_5R = new DecimalFormat("00000");
	public static SimpleDateFormat FORMAT_TIME = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss");

	public static String timeString() {
		return FORMAT_TIME.format(new Date());
	}

	public static int countNumber(String str) {
		int cout = 0;
		char[] chars = str.toCharArray();
		for (int i = 0; i < chars.length; ++i) {
			if (chars[i] >= '0' && chars[i] <= '9')
				cout++;
		}
		return cout;
	}

	public static String removeSpace(String str) {
		return str.replaceAll("[\\t\\n\\r]", " ");
	}

	public static double countNumericPercent(String str) {
		int cout = 0;
		char[] chars = str.toCharArray();
		for (int i = 0; i < chars.length; ++i) {
			if (chars[i] >= '0' && chars[i] <= '9')
				cout++;
		}
		return cout * 1.0 / chars.length;
	}

	public static String replaceLast(String oriString, String pattern, String subsitude) {
		int ind = oriString.lastIndexOf(pattern);
		if (ind < 0)
			return oriString;
		else
			return new StringBuilder(oriString).replace(ind, ind + pattern.length(), subsitude).toString();
	}

	public static String reverse(String str) {
		return new StringBuilder(str).reverse().toString();
	}

	private static RandomString randomString = new RandomString(10);

	public static synchronized String randomString(int length) {
		return randomString.nextString();
	}

	public static class RandomString {

		private static char[] symbols;

		public RandomString(long seed, int length) {
			random = new Random(seed);
			if (length < 1)
				throw new IllegalArgumentException("length < 1: " + length);
			buf = new char[length];
		}

		static {
			StringBuilder tmp = new StringBuilder();
			for (char ch = '0'; ch <= '9'; ++ch)
				tmp.append(ch);
			for (char ch = 'a'; ch <= 'z'; ++ch)
				tmp.append(ch);
			symbols = tmp.toString().toCharArray();
		}

		private Random random;

		private final char[] buf;

		public RandomString(int length) {
			random = new Random();
			if (length < 1)
				throw new IllegalArgumentException("length < 1: " + length);
			buf = new char[length];
		}

		public String nextString() {
			for (int idx = 0; idx < buf.length; ++idx)
				buf[idx] = symbols[random.nextInt(symbols.length)];
			return new String(buf);
		}
	}

	public static String replaceInvalidFileCharacters(String name) {
		return name.replaceAll("[^a-zA-Z0-9.-]", "_");
	}

	public static String parse(String format, Object... params) {
		if (params.length == 0)
			return format;
		ParameterizedMessage msg = new ParameterizedMessage(format, params);
		return msg.getFormattedMessage();
	}

	public static byte[] converteByteString(String hexString) {
		if (hexString == null)
			return new byte[] {};
		int val1, val2;
		char[] chars = hexString.toCharArray();
		byte[] bytes = new byte[chars.length / 2];
		for (int i = 0; i < chars.length; i += 2) {

			if (chars[i] >= 'a')
				val1 = chars[i] - 'a' + 10;
			else
				val1 = chars[i] - '0';

			if (chars[i + 1] >= 'a')
				val2 = chars[i + 1] - 'a' + 10;
			else
				val2 = chars[i + 1] - '0';

			val1 = (val1 << 4) & 0xff;
			bytes[i / 2] = (byte) (val1 | val2);
			// System.out.format("%02x:", bytes[i / 2]);
		}
		// System.out.println();
		// System.out.println(hexString);
		return bytes;
	}

	public static void print(final String msgPattern, final Object... args) {
		System.out.println(format(msgPattern, args));
	}

	public static String format(final String msgPattern, final Object... args) {
		try {
			ParameterizedMessage pm = new ParameterizedMessage(msgPattern, args);
			return pm.getFormattedMessage();
		} catch (final IllegalFormatException ife) {
			return msgPattern;
		}
	}

	public static String[] extractDifferentInMiddle(String s1, String s2) {

		int start = 0;
		for (int i = 0; i < Math.min(s1.length(), s2.length()); ++i) {
			start = i;
			if (s1.charAt(i) != s2.charAt(i)) {
				break;
			}
		}

		int end = 0;
		String rs1 = new StringBuilder(s1).reverse().toString();
		String rs2 = new StringBuilder(s2).reverse().toString();
		for (int i = 0; i < Math.min(rs1.length(), rs2.length()); ++i) {
			end = i;
			if (rs1.charAt(i) != rs2.charAt(i)) {
				break;
			}
		}
		int end1 = s1.length() - end;
		int end2 = s2.length() - end;
		if (start >= Math.min(s1.length(), s2.length()))
			return null;
		if (end1 < 0 || end2 < 0)
			return null;
		return new String[] { s1.substring(start, end1), s2.substring(start, end2) };

	}

	public static String longestCommonNmae(List<String> strings) {
		if (strings.size() == 0) {
			return "";
		}

		for (int prefixLen = 0; prefixLen < strings.get(0).length(); prefixLen++) {
			char c = strings.get(0).charAt(prefixLen);
			for (int i = 1; i < strings.size(); i++) {
				if (prefixLen >= strings.get(i).length() || strings.get(i).charAt(prefixLen) != c) {
					return strings.get(i).substring(0, prefixLen);
				}
			}
		}
		return strings.get(0);
	}

	public static boolean isNumeric(String string) {
		return string.matches("^[-+]?\\d+(\\.\\d+)?$");
	}

}
