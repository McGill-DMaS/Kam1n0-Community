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

import java.nio.charset.Charset;
import java.util.Random;

import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashFunction;

import com.google.common.hash.Hashing;

public class MD5HashFunction extends HashFunction {

	private com.google.common.hash.HashFunction md5;

	public MD5HashFunction(Random random) {
		super(random);
		this.md5 = Hashing.md5();
	}

	@Override
	public int hash(byte[] bytes) {
		return md5.hashBytes(bytes).asInt();
	}

	@Override
	public int hash(String str) {
		return md5.hashString(str, Charset.defaultCharset()).asInt();
	}
}