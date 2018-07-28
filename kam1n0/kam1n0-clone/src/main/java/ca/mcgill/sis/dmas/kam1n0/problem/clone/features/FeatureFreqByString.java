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
import java.util.List;
import java.util.Set;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

import com.google.common.collect.ImmutableMap;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

public class FeatureFreqByString extends Features {

	private static final long serialVersionUID = -187209579406593133L;
	@XStreamOmitField
	List<String> features;

	public FeatureFreqByString(Set<String> vals) {
		features = new ArrayList<>(vals);
	}

	@Override
	public List<String> getFeatures(AsmLineNormalizer normalizer) {
		return features;
	}

	@Override
	public void update(SparseVector vec, List<List<String>> blk, ImmutableMap<String, Integer> featMap) {
		blk.stream().flatMap(List::stream).forEach(tkn -> {
			Integer ind = featMap.get(tkn);
			if (ind != null)
				vec.inc(ind);
		});

	}

}
