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
package ca.mcgill.sis.dmas.nlp.model.astyle;

import static java.lang.Math.sqrt;

import java.io.File;

import static java.lang.Math.pow;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;

public class MathUtilities {

	private static Logger logger = LoggerFactory.getLogger(MathUtilities.class);

	public static int EXP_TABLE_SIZE = 1000;
	public static int MAX_EXP = 6;
	public static double[] expTable = null;

	public static void createExpTable() {
		expTable = new double[EXP_TABLE_SIZE];
		for (int i = 0; i < EXP_TABLE_SIZE; i++) {
			expTable[i] = Math.exp(((i / (double) EXP_TABLE_SIZE * 2 - 1) * MAX_EXP));
			expTable[i] = expTable[i] / (expTable[i] + 1);
		}
	}

	public static <T> Iterable<EntryPair<T, List<T>>> slidingWnd(List<T> input, int window, RandL rl) {
		return () -> IntStream.range(0, input.size()).mapToObj(//
				ind -> {// *
					int b = rl.nextResidue(window);//
					ArrayList<T> subList = new ArrayList<>();
					int startIndex = ind - window + b >= 0 ? // inclusive
					ind - window + b : 0;
					int endIndex = ind + window - b + 1 <= input.size() ? // exclusive
					ind + window - b + 1 : input.size();
					for (int i = startIndex; i < endIndex; ++i)
						if (i != ind)
							subList.add(input.get(i));
					// System.out.println(input.toString());
					// System.out.println(input.get(ind).toString() + " - " +
					// subList.toString());
					// System.out.println("");
					return new EntryPair<T, List<T>>(input.get(ind), subList);
				}).iterator();
	}

	public static <T> Iterable<EntryPair<T, List<T>>> slidingWnd(List<T> input, int window, RandL rl, T pad) {
		if (input.size() < 1)
			return new ArrayList<>();
		else if (window < 0)
			return Arrays.asList(new EntryPair<T, List<T>>(input.get(input.size() / 2), input));
		else
			return () -> IntStream.range(0, input.size()).mapToObj(//
					ind -> {// *
						int b = rl == null ? 0 : rl.nextResidue(window);//
						ArrayList<T> subList = new ArrayList<>();
						int startIndex = ind - window + b >= 0 ? // inclusive
						ind - window + b : 0;
						int endIndex = ind + window - b + 1 <= input.size() ? // exclusive
						ind + window - b + 1 : input.size();
						for (int i = startIndex; i < endIndex; ++i)
							if (i != ind)
								subList.add(input.get(i));
						// System.out.println(input.toString());
						// System.out.println(input.get(ind).toString() + " - "
						// +
						// subList.toString());
						// System.out.println("");
						if (rl == null && pad != null)
							while (subList.size() < window * 2)
								subList.add(pad);
						return new EntryPair<T, List<T>>(input.get(ind), subList);
					}).iterator();
	}

	public static final Predicate<Object> notNull = o -> o != null;

	public static double dot(double[] vec1, double[] vec2) {
		double sum = 0;
		for (int i = 0; i < vec1.length; ++i)
			sum += vec1[i] * vec2[i];
		return sum;
	}

	public static void dxpay(double[] v1, double[] v2, double g) {
		for (int i = 0; i < v1.length; ++i)
			v1[i] += v2[i] * g;
	}

	public static void add(double[] v1, double[] v2) {
		for (int i = 0; i < v1.length; ++i)
			v1[i] += v2[i];
	}

	public static void sub(double[] v1, double[] v2) {
		for (int i = 0; i < v1.length; ++i)
			v1[i] -= v2[i];
	}

	public static double exp(double f) {
		double v;
		if (f > MAX_EXP)
			v = 1;
		else if (f < -MAX_EXP)
			v = 0;
		else
			v = expTable[(int) ((f + MAX_EXP) * (EXP_TABLE_SIZE / MAX_EXP / 2))];
		return v;
		// f = Math.exp(f);
		// f = f / (f + 1);
		// return f;
	}

	public static double[] normalize(double[] vec) {
		double len = 0;
		for (int j = 0; j < vec.length; ++j)
			len += vec[j] * vec[j];
		len = sqrt(len);
		for (int j = 0; j < vec.length; ++j)
			vec[j] /= len;
		return vec;
	}

	public static double[] cp(double[] vec) {
		return Arrays.copyOf(vec, vec.length);
	}

	public static boolean areZeros(double[] vec) {
		for (int i = 0; i < vec.length; ++i)
			if (vec[i] != 0)
				return false;
		return true;
	}

	public static void div(double[] vec, double conts) {
		for (int i = 0; i < vec.length; ++i)
			vec[i] /= conts;
	}

	public static void mlp(double[] vec, double conts) {
		for (int i = 0; i < vec.length; ++i)
			vec[i] *= conts;
	}

	public static double[] avg(List<double[]> vecs, int vec_dim) {
		double[] sum = sum(vecs, vec_dim);
		if (vecs.size() > 1)
			div(sum, vecs.size() * 1.0);
		return sum;
	}

	public static double[] sum(List<double[]> vecs, int vec_dim) {
		if (vecs.size() < 1) {
			double[] vec = new double[vec_dim];
			Arrays.fill(vec, 0);
			return vec;
		}
		double[] sum = new double[vec_dim];
		for (double[] vec : vecs)
			add(sum, vec);
		return sum;
	}

	public static int[] createPTbl(List<NodeWord> mp, int size, double power) {
		int[] tbl = new int[size];
		double train_word_pows = mp.stream().mapToDouble(w -> pow(w.freq, power)).sum();
		int ind = 0;
		double cp = pow(mp.get(ind).freq, power) / train_word_pows;
		for (int a = 0; a < size; ++a) {
			tbl[a] = ind;
			if (a * 1.0 / size > cp && ind < mp.size() - 1) {
				ind++;
				cp += pow(mp.get(ind).freq, power) / train_word_pows;
			} else if (ind == mp.size() - 1) {
				Arrays.fill(tbl, a, size, ind);
				break;
			}
		}
		return tbl;
	}

	public static int[] createPTblForNodeWord3(List<NodeWord3> mp, int size, double power) {
		int[] tbl = new int[size];
		double train_word_pows = mp.stream().mapToDouble(w -> pow(w.freq, power)).sum();
		int ind = 0;
		double cp = pow(mp.get(ind).freq, power) / train_word_pows;
		for (int a = 0; a < size; ++a) {
			tbl[a] = ind;
			if (a * 1.0 / size > cp && ind < mp.size() - 1) {
				ind++;
				cp += pow(mp.get(ind).freq, power) / train_word_pows;
			} else if (ind == mp.size() - 1) {
				Arrays.fill(tbl, a, size, ind);
				break;
			}
		}
		return tbl;
	}

	public static double[] convertToFloat(double[] vec) {
		double[] nvec = new double[vec.length];
		for (int i = 0; i < vec.length; ++i) {
			float fval = (float) vec[i];
			nvec[i] = fval;
		}
		return nvec;
	}

	public static double[] concate(double[] vec1, double[] vec2) {
		double[] vals = new double[vec1.length + vec2.length];
		for (int i = 0; i < vec1.length; ++i) {
			vals[i] = vec1[i];
		}
		for (int j = 0; j < vec2.length; ++j) {
			vals[vec1.length + j] = vec2[j];
		}
		return vals;
	}

	public static double[] concate(Iterable<double[]> vecs) {
		int length = StreamSupport.stream(vecs.spliterator(), false).mapToInt(vec -> vec.length).sum();
		double[] vals = new double[length];
		int offset = 0;
		for (double[] vec : vecs) {
			for (int i = 0; i < vec.length; ++i)
				vals[i + offset] = vec[i];
			offset += vec.length;
		}
		return vals;
	}

	public static Map<String, double[]> normalize(Map<String, double[]> map) {
		map.values().stream().forEach(MathUtilities::normalize);
		return map;
	}

	public static Map<String, double[]> cleanNAN(Map<String, double[]> map) {
		map.values().stream().forEach(vec -> {
			for (int i = 0; i < vec.length; ++i)
				if (Double.isNaN(vec[i]) || Double.isInfinite(vec[i]))
					vec[i] = 0;
		});
		return map;
	}

	public static Map<String, double[]> normalizeAttrZeroOne(Map<String, double[]> map) {
		int dim = map.values().iterator().next().length;
		double[] maxs = new double[dim];
		double[] mins = new double[dim];
		Arrays.fill(maxs, Double.MIN_VALUE);
		Arrays.fill(mins, Double.MAX_VALUE);
		map.forEach((k, v) -> {
			for (int i = 0; i < dim; ++i) {
				double val = v[i];
				if (!Double.isFinite(val))
					continue;
				if (val > maxs[i])
					maxs[i] = val;
				if (val < mins[i])
					mins[i] = val;
			}
		});
		map.values().forEach(v -> {
			for (int i = 0; i < dim; ++i) {
				v[i] = (v[i] - mins[i]) / (maxs[i] - mins[i]);
			}
		});
		return map;
	}

	@SafeVarargs
	public static Map<String, double[]> merge(Boolean normalize, Map<String, double[]>... maps) {
		return maps[0].entrySet().stream().map(ent -> {
			List<double[]> list = Arrays.stream(maps).map(map -> map.get(ent.getKey())).collect(Collectors.toList());
			if (normalize)
				return new EntryPair<>(ent.getKey(), normalize(concate(list)));
			else
				return new EntryPair<>(ent.getKey(), concate(list));
		}).collect(Collectors.toMap(ent -> ent.key, ent -> ent.value));
	}

	public static Map<String, double[]> merge(Boolean normalize, List<Map<String, double[]>> maps) {
		return maps.stream().findAny().get().entrySet().stream().map(ent -> {
			List<double[]> list = maps.stream().map(map -> map.get(ent.getKey())).collect(Collectors.toList());
			if (normalize)
				return new EntryPair<>(ent.getKey(), normalize(concate(list)));
			else
				return new EntryPair<>(ent.getKey(), concate(list));
		}).collect(Collectors.toMap(ent -> ent.key, ent -> ent.value));
	}

	public static void saveEmbedding(String file, Map<String, double[]> map) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			File outfile = new File(file);
			outfile.getParentFile().mkdirs();
			mapper.writeValue(outfile, map);
		} catch (Exception e) {
			logger.error("Failed to save embedding...", e);
		}
	}

	public static Map<String, double[]> readEmbedding(String file) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			File infile = new File(file);
			TypeReference<HashMap<String, double[]>> typeRef = new TypeReference<HashMap<String, double[]>>() {
			};
			return mapper.readValue(infile, typeRef);
		} catch (Exception e) {
			logger.error("Failed to save embedding...", e);
			return null;
		}
	}

	public static int maxIndex(double[] vec) {
		int ind = 0;
		if (vec.length < 0)
			return -1;
		for (int i = 0; i < vec.length; ++i)
			if (vec[ind] < vec[i])
				ind = i;
		return ind;
	}
}
