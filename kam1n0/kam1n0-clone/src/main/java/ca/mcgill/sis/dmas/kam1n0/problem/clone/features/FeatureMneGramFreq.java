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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.features;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import com.google.common.collect.ImmutableMap;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class FeatureMneGramFreq extends Features {

	private static final long serialVersionUID = 2520678943477192981L;
	@XStreamOmitField
	List<String> features;
	public int n;

	public FeatureMneGramFreq(int n) {
		this.n = n;
	}

	@Override
	public List<String> getFeatures(AsmLineNormalizer normalizer) {
		if (this.features == null)
			this.features = constructFeature(n, normalizer);
		return this.features;
	}

	@Override
	public void update(SparseVector vec, List<List<String>> blk, ImmutableMap<String, Integer> featMap) {
		// double[] score = new double[Dimension];
		Queue<String> window = new LinkedList<>();
		for (List<String> tokens : blk) {
			window.add(tokens.get(0));
			if (window.size() == n) {
				String identifier = StringResources.JOINER_TOKEN_CSV.join(window);
				Integer index = featMap.get(identifier);
				if (index != null)
					vec.inc(index);// score[index]++;
				// else
				// System.out.println(identifier);
				window.poll();
			}
		}
	}

	public static ArrayList<String> constructFeature(int n, AsmLineNormalizer normalizer) {
		ArrayList<String> feats = new ArrayList<>();

		// n-grams
		if (n >= 1) {
			List<String> cmbs = DmasCollectionOperations
					.combinationDuplicated(normalizer.res.getALLOperations(normalizer.setting.normalizeOperation), n);
			cmbs.forEach(ls -> {
				feats.add(ls);
			});
		}

		return feats;
	}

}
