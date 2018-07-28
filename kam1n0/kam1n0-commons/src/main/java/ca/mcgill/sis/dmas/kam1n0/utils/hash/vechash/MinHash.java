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

import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;


import ca.mcgill.sis.dmas.io.array.DmasVectorDistances;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashFunction.HashFunctionType;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class MinHash extends HashSchema {

	private static final long serialVersionUID = -5758231095417635118L;
	private HashFunction[] functions;
	private int[][] matrix;
	private int vecDim = 0;

	public MinHash(List<String> features, int numberOfBits, Random random) {
		super(numberOfBits);
		functions = HashFunction.getHashFunctions(random, this.numberOfBits, HashFunctionType.Murmur_64);
		vecDim = features.size();
		matrix = new int[this.numberOfBits / 32][features.size()];
		IntStream.range(0, numberOfBits / 32).parallel()
				.forEach(ind -> IntStream.range(0, features.size()).forEach(fInd -> {
					matrix[ind][fInd] = functions[ind].hash(features.get(fInd));
				}));
	}

	@Override
	public byte[] hash(double[] vector) {
		byte[] bytes = new byte[this.numberOfBits / 8];
		for (int i = 0; i < this.numberOfBits / 32; ++i) {
			int min = Integer.MAX_VALUE;
			for (int j = 0; j < this.vecDim; ++j) {
				if (vector[j] != 0)
					min = min < matrix[i][j] ? min : matrix[i][j];
			}
			bytes[i * 4] = (byte) (min >> 24);
			bytes[i * 4 + 1] = (byte) (min >> 16);
			bytes[i * 4 + 2] = (byte) (min >> 8);
			bytes[i * 4 + 3] = (byte) min;
		}
		return bytes;
	}

	@Override
	public String getParams() {
		return "HSchema=Minhash";
	}

	@Override
	public double distApprox(byte[] bv1, byte[] bv2, int length) {
		double sum = 0;
		for (int i = 0; i < this.numberOfBits / 32; ++i) {
			int h1 = DmasByteOperation.fromByte(bv1, i * 4);
			int h2 = DmasByteOperation.fromByte(bv2, i * 4);
			if (h1 == h2)
				sum++;
		}
		return sum / (this.numberOfBits / 32);

	}

	@Override
	public double distReal(double[] v1, double[] v2) {
		return DmasVectorDistances.jaccard(v1, v2) / v1.length;
	}

	public static void main(String[] args) {
		// MinHash m = new MinHash(
		// FeatureGenerators.genFeqByString("a", "b", "c", "d", "e", "f", "g",
		// "h", "i", "j", "k", "l"),
		// 32 * 100000, new Random(123));
		// String[] a1 = { "a", "b", "c", "d", "e", "f", "g" };
		// String[] a2 = { "a", "d", "f", "g", "k" };
		// String[] a3 = { "h", "i", "j", "k", "l", "a" };
		// logger.info("");
		// // logger.info("{}", m.hash(Arrays.asList(a1)));
		// // logger.info("{}", m.hash(Arrays.asList(a2)));
		// // logger.info("{}", m.hash(Arrays.asList(a3)));
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

	@Override
	public byte[] hash(double[] vector, int numberOfBits) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] hash(SparseVector vec, int numberOfBits) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public double distReal(SparseVector v1, SparseVector v2) {
		// TODO Auto-generated method stub
		return 0;
	}

}
