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

import java.util.Random;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.utils.hash.functions.DefaultHashFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.functions.UniversalHashFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.functions.MD5HashFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.functions.MurmurHashFunction;

public abstract class HashFunction {

	private static Logger logger = LoggerFactory.getLogger(HashFunction.class);

	public HashFunction(Random random) {
		this.random = random;
	}

	protected Random random;

	public abstract int hash(byte[] bytes);

	public abstract int hash(String str);

	public static enum HashFunctionType {
		Universal_64, Murmur_64, MD5_64, JavaDefault_32;
		public static String[] names() {
			HashFunctionType[] states = HashFunctionType.values();
			String[] names = new String[states.length];
			for (int i = 0; i < states.length; i++) {
				names[i] = states[i].name();
			}
			return names;
		}
	}

	public static HashFunction getHashFunction(long seed, HashFunctionType type) {
		Random random = new Random(seed);
		return getHashFunction(random, type);
	}

	public static HashFunction[] getHashFunctions(Random random, int size,
			HashFunctionType type) {
		HashFunction[] functions = new HashFunction[size];
		IntStream.range(0, size).forEach(
				ind -> functions[ind] = getHashFunction(random, type));
		return functions;
	}

	public static HashFunction getHashFunction(Random random,
			HashFunctionType type) {
		switch (type) {
		case Universal_64:
			return new UniversalHashFunction(random);
		case Murmur_64:
			return new MurmurHashFunction(random);
		case MD5_64:
			return new MD5HashFunction(random);
		case JavaDefault_32:
			return new DefaultHashFunction(random);
		default:
			logger.error("Failed to find corresponding hashing type: {}", type);
			return new MurmurHashFunction(random);
		}
	}
}
