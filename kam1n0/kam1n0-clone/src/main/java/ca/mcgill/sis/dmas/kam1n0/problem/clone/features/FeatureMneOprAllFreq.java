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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

import com.google.common.collect.ImmutableMap;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

public class FeatureMneOprAllFreq extends Features {

	private static final long serialVersionUID = -5604699149842204077L;
	private static Logger logger = LoggerFactory.getLogger(FeatureMneOprAllFreq.class);
	@XStreamOmitField
	List<String> features;

	public FeatureMneOprAllFreq() {

	}

	@Override
	public List<String> getFeatures(AsmLineNormalizer normalizer) {
		if (this.features == null)
			this.features = constructFeature(normalizer);
		return this.features;
	}

	@Override
	public void update(SparseVector vec, List<List<String>> blk, ImmutableMap<String, Integer> featMap) {
		for (List<String> tokens : blk) {
			String feat = tokens.get(0);
			if (tokens.size() > 1) {
				feat = feat + "," + tokens.get(1);
			}
			if (tokens.size() > 2) {
				feat = feat + "," + tokens.get(2);
			}
			Integer index = featMap.get(feat);
			if (index != null)
				vec.inc(index);// score[index]++;
			else
				System.out.println("Feature not found: [" + feat.toString() + "] from " + tokens.toString());
		}
		if (vec.noEntry())
			System.out.println("Zero vector found for " + blk);

	}

	public static ArrayList<String> constructFeature(AsmLineNormalizer normalizer) {
		ArrayList<String> feats = new ArrayList<>();

		ArrayList<String> mns = FeatureMneFreq.constructFeature(normalizer);
		mns.add(AsmLineNormalizationResource.NORM_UNIDF);
		feats.addAll(mns);

		ArrayList<String> operandTypes = FeatureOprFreq.constructFeature(normalizer);
		operandTypes.add(AsmLineNormalizationResource.NORM_CONST);
		operandTypes.add(AsmLineNormalizationResource.NORM_UNIDF);

		// combination of mnem and first operand:
		for (String mnem : mns) {
			for (String otype : operandTypes) {
				feats.add(mnem + "," + otype);
			}
		}

		// combination of all
		for (String mnem : mns) {
			for (String otype : operandTypes) {
				for (String otype2 : operandTypes) {
					feats.add(mnem + "," + otype + "," + otype2);
				}
			}
		}

		return feats;
	}

}
