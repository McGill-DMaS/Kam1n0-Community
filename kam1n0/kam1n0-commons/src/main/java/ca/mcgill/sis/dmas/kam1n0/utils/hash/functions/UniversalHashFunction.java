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
package ca.mcgill.sis.dmas.kam1n0.utils.hash.functions;

import java.util.Random;

import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;

public class UniversalHashFunction extends HashFunction {

	private int a, b;

	public UniversalHashFunction(Random random) {
		super(random);
		a = 0;
		while (a % 1 == 1 || a <= 0)
			a = random.nextInt();
		b = 0;
		while (b <= 0)
			b = random.nextInt();
	}

	@Override
	public int hash(byte[] bytes) {
		long hashValue = 31;
		for (byte byteVal : bytes) {
			hashValue = hashValue * a + byteVal;
			hashValue = hashValue % HashUtils.MAX_INT_SMALLER_TWIN_PRIME;
			// hashValue *= a * byteVal;
			// hashValue += b;
		}
		return Math
				.abs((int) (hashValue % HashUtils.MAX_INT_SMALLER_TWIN_PRIME));
	}

	@Override
	public int hash(String str) {
		return this.hash(str.getBytes());
	}

}