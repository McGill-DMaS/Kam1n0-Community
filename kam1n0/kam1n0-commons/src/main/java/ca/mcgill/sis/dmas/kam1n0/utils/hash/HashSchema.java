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

import java.io.Serializable;
import java.util.List;
import java.util.Random;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.vechash.MinHash;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.vechash.SimHash;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.vechash.SimHashBitSet;

public abstract class HashSchema implements Serializable {

	private static final long serialVersionUID = 7447631229671617940L;

	public static enum HashSchemaTypes {
		SimHash, MinHash, PStable

	};

	public static HashSchema getHashSchema(List<String> features, HashSchemaTypes type, int numberOfBits,
			Random random) {
		switch (type) {
		case SimHash:
			return new SimHashBitSet(features, numberOfBits, random);
		case MinHash:
			return new MinHash(features, numberOfBits, random);
		default:
			return new SimHash(features, numberOfBits, random);
		}
	}

	// private static Logger logger = LoggerFactory.getLogger(HashSchema.class);

	protected int numberOfBits = 1;

	public HashSchema(int numberOfBits) {
		// if (numberOfBits % 8 != 0) {
		// numberOfBits = numberOfBits / 8 * 8;
		// logger.error("Number of bits should be exact multiplier of 8.
		// Changing to {}", numberOfBits);
		// }
		this.numberOfBits = numberOfBits;
	}

	public abstract String getParams();

	public abstract byte[] hash(double[] vector, int numberOfBits);

	public abstract byte[] hash(SparseVector vec, int numberOfBits);

	public byte[] hash(double[] vector) {
		return hash(vector, this.getNumberOfBits());
	}

	public byte[] hash(SparseVector vector) {
		return hash(vector, this.getNumberOfBits());
	}

	public abstract double distApprox(byte[] v1, byte[] v2, int length);

	public abstract double distReal(double[] v1, double[] v2);

	public double distReal(SparseVector v1, SparseVector v2) {
		return v1.cosine(v2);
	}

	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("bits=", this.numberOfBits, getParams());
	}

	public int getNumberOfBits() {
		return numberOfBits;
	}

}
