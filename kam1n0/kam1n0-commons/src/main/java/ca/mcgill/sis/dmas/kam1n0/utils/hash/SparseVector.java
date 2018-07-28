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
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Set;

import scala.Tuple2;

public class SparseVector implements Serializable {

	private static final long serialVersionUID = -3469068223636688322L;

	HashMap<Integer, Double> map = new HashMap<>();

	public Set<Integer> indexs() {
		return map.keySet();
	}

	public int dim = 0;

	public boolean noEntry() {
		if (map.size() == 0)
			return true;
		return false;
	}

	public SparseVector(int dim) {
		this.dim = dim;
	}

	public double get(int ind) {
		Double val = map.get(ind);
		if (val == null)
			return 0;
		else
			return val;
	}

	public double[] toArray() {
		double[] vals = new double[dim];
		Arrays.fill(vals, 0);
		map.entrySet().stream().forEach(ent -> vals[ent.getKey()] = ent.getValue());
		return vals;
	}

	public void set(int ind, double val) {
		map.put(ind, val);
	}

	public void inc(int ind) {
		map.compute(ind, (k, v) -> v == null ? 1 : v + 1);
	}

	public double dot(double[] vec) {
		return map.entrySet().stream().mapToDouble(ent -> vec[ent.getKey()] * ent.getValue()).sum();
	}

	public double dot(BitSet vec) {
		return map.entrySet().stream().mapToDouble(ent -> (vec.get(ent.getKey()) ? 1 : -1) * ent.getValue()).sum();
	}

	public double dot(byte[] vec) {
		return map.entrySet().stream().mapToDouble(ent -> vec[ent.getKey()] * ent.getValue()).sum();
	}

	public double cosine(SparseVector vec) {
		double tnorm = this.map.entrySet().stream().mapToDouble(ent -> ent.getValue() * ent.getValue()).sum();
		double gnorm = vec.map.entrySet().stream().mapToDouble(ent -> ent.getValue() * ent.getValue()).sum();
		double dotp = map.entrySet().stream().map(ent -> new Tuple2<>(ent.getValue(), vec.map.get(ent.getKey())))
				.filter(tp -> tp._1 != null && tp._2 != null).mapToDouble(tp -> tp._1 * tp._2).sum();
		return dotp / (Math.sqrt(tnorm) * Math.sqrt(gnorm));
	}
}
