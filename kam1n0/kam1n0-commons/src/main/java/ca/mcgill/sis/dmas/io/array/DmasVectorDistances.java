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
package ca.mcgill.sis.dmas.io.array;

import java.util.BitSet;

import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;

public class DmasVectorDistances {

	public static double cosine(double[] v1, double[] v2) {
		double sum = 0;
		for (int i = 0; i < v1.length; ++i)
			sum += v1[i] * v2[i];
		return sum / (mode(v1, 2) * mode(v2, 2));
	}

	public static double jaccard(double[] v1, double[] v2) {
		double sum = 0;
		for (int i = 0; i < v1.length; ++i) {
			if (v1[i] != 0 && v2[i] != 0)
				sum++;
		}
		return sum;
	}

	public static double mode(double[] v, int dim) {
		double sum = 0;
		for (int i = 0; i < v.length; ++i)
			sum += Math.pow(v[i], dim);
		return Math.pow(sum, 1.0 / dim);
	}

	public static double dot(double[] v1, double[] v2) {
		double sum = 0;
		for (int i = 0; i < v1.length; ++i)
			sum += v1[i] * v2[i];
		return sum;

	}

	public static double dot(double[] v1, BitSet v2) {
		double sum = 0;
		for (int i = 0; i < v1.length; ++i)
			sum += v1[i] * (v2.get(i) ? 1 : -1);
		return sum;

	}

	public static int hamming(byte[] by1, byte[] by2) {
		int sum = 0;
		for (int i = 0; i < by1.length / 4 + 1; ++i) {
			int v1 = DmasByteOperation.fromByte(by1, i * 4);
			int v2 = DmasByteOperation.fromByte(by2, i * 4);
			sum += Integer.bitCount(v1 ^ v2);
		}
		return sum;
	}

	public static double dot(double[] v1, byte[] v2) {
		double sum = 0;
		for (int i = 0; i < v1.length; ++i)
			sum += v1[i] * v2[i];
		return sum;
	}

}
