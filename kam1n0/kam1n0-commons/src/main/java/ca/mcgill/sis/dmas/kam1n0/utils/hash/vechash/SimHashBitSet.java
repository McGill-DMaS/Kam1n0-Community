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
package ca.mcgill.sis.dmas.kam1n0.utils.hash.vechash;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

import ca.mcgill.sis.dmas.io.array.DmasVectorDistances;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class SimHashBitSet extends HashSchema {

	private static final long serialVersionUID = -7304813354345118266L;

	public SimHashBitSet(List<String> features, int numberOfBits, Random random) {
		super(numberOfBits);
		this.numberOfFeatures = features.size();
		hyperplanes = new ArrayList<>(this.numberOfBits);// new
															// byte[this.numberOfBits][numberOfFeatures];
		IntStream.range(0, this.numberOfBits).forEach(hId -> hyperplanes.add(new BitSet()));
		IntStream.range(0, this.numberOfBits).forEach(hId -> {
			BitSet set = hyperplanes.get(hId);
			for (int fId = 0; fId < features.size(); ++fId)
				set.set(fId, random.nextBoolean());
		});
	}

	private List<BitSet> hyperplanes;
	public int numberOfFeatures;

	@Override
	public String getParams() {
		return "HSchema=Simhash";
	}

	@Override
	public byte[] hash(double[] vector, int numberOfBits) {
		int residual = numberOfBits % 8;
		int bytes = numberOfBits / 8;
		if (residual != 0)
			bytes++;
		byte[] rslt = new byte[bytes];
		int i = 0;
		for (; i < numberOfBits / 8; ++i) {
			rslt[i] = 0x00;
			for (int j = 0; j < 8; j++) {
				if (DmasVectorDistances.dot(vector, hyperplanes.get(i * 8 + j)) > 0) {
					rslt[i] |= (0x01 << j);
				}
			}
		}
		if (residual != 0) {
			rslt[i] = 0x00;
			for (int j = 0; j < residual; j++) {
				if (DmasVectorDistances.dot(vector, hyperplanes.get(i * 8 + j)) > 0) {
					rslt[i] |= (0x01 << j);
				}
			}
		}
		return rslt;
	}

	@Override
	public byte[] hash(SparseVector vec, int numberOfBits) {
		int residual = numberOfBits % 8;
		int bytes = numberOfBits / 8;
		if (residual != 0)
			bytes++;
		byte[] rslt = new byte[bytes];
		int i = 0;
		for (; i < numberOfBits / 8; ++i) {
			rslt[i] = 0x00;
			for (int j = 0; j < 8; j++) {
				if (vec.dot(hyperplanes.get(i * 8 + j)) > 0) {
					rslt[i] |= (0x01 << j);
				}
			}
		}
		if (residual != 0) {
			rslt[i] = 0x00;
			for (int j = 0; j < residual; j++) {
				if (vec.dot(hyperplanes.get(i * 8 + j)) > 0) {
					rslt[i] |= (0x01 << j);
				}
			}
		}
		return rslt;
	}

	@Override
	public double distReal(SparseVector v1, SparseVector v2) {
		return v1.cosine(v2);
	}

	@Override
	public double distApprox(byte[] by1, byte[] by2, int length) {
		int sum = 0;
		for (int i = 0; i < length; ++i) {
			if (by1[i] == by2[i])
				sum += 8;
			else {
				sum += 8 - DmasByteOperation.hamming(by1[i], by2[i]);
				break;
			}
		}
		return sum * 1.0 / (length * 8);
	}

	@Override
	public double distReal(double[] v1, double[] v2) {
		return DmasVectorDistances.cosine(v1, v2);
	}

	public static void main(String[] args) {
		// SimHash m = new SimHash(
		// FeatureGenerators.genFeqByString("a", "b", "c", "d", "e", "f", "g",
		// "h", "i", "j", "k", "l"), 8,
		// new Random(100));
		// String[] a1 = { "a", "b", "c", "d", "e", "f", "g" };
		// String[] a2 = { "a", "b", "c", "d", "e", "f", "h" };
		// String[] a3 = { "h", "i", "j", "k", "l" };
		//
		// logger.info("");
		// logger.info("{}",
		// DmasByteOperation.toHexs(m.hash(Arrays.asList(a1))));
		// logger.info("{}",
		// DmasByteOperation.toHexs(m.hash(Arrays.asList(a2))));
		// logger.info("{}",
		// DmasByteOperation.toHexs(m.hash(Arrays.asList(a3))));
		//
		// logger.info("{}",
		// DmasByteOperation.toBinary(m.hash(Arrays.asList(a1))));
		// logger.info("{}",
		// DmasByteOperation.toBinary(m.hash(Arrays.asList(a2))));
		// logger.info("{}",
		// DmasByteOperation.toBinary(m.hash(Arrays.asList(a3))));
		//
		// logger.info("a1 vs a2: {} - {}", m.distReal(Arrays.asList(a1),
		// Arrays.asList(a2)),
		// m.distApprox(Arrays.asList(a1), Arrays.asList(a2)));
		//
		// logger.info("a1 vs a3: {} - {}", m.distReal(Arrays.asList(a1),
		// Arrays.asList(a3)),
		// m.distApprox(Arrays.asList(a1), Arrays.asList(a3)));
		//
		// logger.info("a2 vs a3: {} - {}", m.distReal(Arrays.asList(a2),
		// Arrays.asList(a3)),
		// m.distApprox(Arrays.asList(a2), Arrays.asList(a3)));
	}

}
