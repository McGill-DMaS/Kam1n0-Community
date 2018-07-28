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
package ca.mcgill.sis.dmas.kam1n0.utils.hash;

import com.google.common.hash.Hashing;

public class HashUtils {

	public static volatile com.google.common.hash.HashFunction defaultHashFuncForIdGen = Hashing
			.murmur3_128(1234);

	public static long constructID(byte[]... bytes) {
		int size = 0;
		for (int i = 0; i < bytes.length; ++i) {
			size += bytes[i].length;
		}
		byte[] destination = new byte[size];
		size = 0;
		for (int i = 0; i < bytes.length; ++i) {
			System.arraycopy(bytes[i], 0, destination, size, bytes[i].length);
			size += bytes[i].length;
		}
		return defaultHashFuncForIdGen.hashBytes(destination).asLong();
	}

	public static long hashTkns(Iterable<? extends Iterable<String>> strs) {
		long hashCode = 1;
		for (Iterable<String> line : strs)
			for (String tkn : line)
				hashCode = 31 * hashCode + hashStrToLong(tkn);
		return hashCode;
	}

	public static long hashStrToLong(String string) {
		long h = 1125899906842597L; // prime
		int len = string.length();

		for (int i = 0; i < len; i++) {
			h = 31 * h + string.charAt(i);
		}
		return h;
	}

	public final static long MAX_INT_SMALLER_TWIN_PRIME = 2147482949l;

	public static void main(String[] args) {
		System.out.println(constructID("this is a sample string".getBytes()));
	}

}
