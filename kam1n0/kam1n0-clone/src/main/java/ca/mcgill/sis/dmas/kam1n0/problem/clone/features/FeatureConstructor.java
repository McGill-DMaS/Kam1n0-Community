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

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;
import com.google.common.collect.ImmutableList;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragmentNormalized;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class FeatureConstructor implements Serializable {

	private static Logger logger = LoggerFactory.getLogger(FeatureConstructor.class);

	private static final long serialVersionUID = -8224564861042639052L;

	ImmutableMap<String, Integer> featMap;

	public AsmLineNormalizer normalizer;
	public final int dimensionality;
	public final List<Features> features;
	public ImmutableList<String> featureElements;

	public String getFeature(int index) {
		if (index < 0 || index > featureElements.size() - 1)
			return null;
		else
			return featureElements.get(index);
	}

	public int getFeatureIndex(String feature) {
		Integer ind = featMap.get(feature);
		if (ind == null)
			return -1;
		else
			return ind;
	}

	public FeatureConstructor(AsmLineNormalizer normalizer, Features... features) {
		this(normalizer, Arrays.asList(features));
	}

	public FeatureConstructor(AsmLineNormalizer normalizer, List<Features> features) {
		this.normalizer = normalizer;
		this.features = features;
		List<String> feats = features.stream().flatMap(feat -> feat.getFeatures(normalizer).stream())
				.collect(Collectors.toList());
		this.featureElements = ImmutableList.copyOf(feats);
		Builder<String, Integer> builder = ImmutableMap.<String, Integer>builder();
		for (int i = 0; i < feats.size(); ++i) {
			builder.put(feats.get(i), i);
		}
		featMap = builder.build();
		this.dimensionality = featMap.size();
		logger.info("Feature Constructor initialized. {} features in total.", featMap.size());
	}

	public SparseVector scoreNormalizedFragments(Iterable<AsmFragmentNormalized> tokenizedFrags) {
		SparseVector vec = new SparseVector(this.dimensionality);
		for (AsmFragmentNormalized frag : tokenizedFrags) {
			features.forEach(feat -> feat.update(vec, frag.asmLines, this.featMap));
		}
		return vec;
	}

	public SparseVector scoreNormalizedFragment(AsmFragmentNormalized frag) {
		SparseVector vec = new SparseVector(this.dimensionality);
		features.forEach(feat -> feat.update(vec, frag.asmLines, this.featMap));
		return vec;
	}

	public SparseVector score(Function function) {
		return scoreNormalizedFragments(normalizer.tokenizeAsmFragments(function));
	}

	public SparseVector score(Block blk) {
		return scoreNormalizedFragment(normalizer.tokenizeAsmFragment(blk));
	}

	public List<String> tokenizeAsmLine(List<String> asmLine) {
		return normalizer.tokenizeAsmLine(asmLine);
	}

	public Iterable<List<String>> tokenizeAsmLines(Iterable<? extends List<String>> asmlines) {
		return normalizer.tokenizeAsmLines(asmlines);
	}

	public Iterable<AsmFragmentNormalized> tokenizeAsmFragments(Iterable<? extends AsmFragment> frags) {
		return normalizer.tokenizeAsmFragments(frags);
	}

	public AsmFragmentNormalized tokenizeAsmFragment(AsmFragment fra) {
		return normalizer.tokenizeAsmFragment(fra);
	}

}
