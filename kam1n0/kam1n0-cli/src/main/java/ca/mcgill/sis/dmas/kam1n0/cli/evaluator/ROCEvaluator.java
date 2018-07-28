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
package ca.mcgill.sis.dmas.kam1n0.cli.evaluator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.cli.evaluator.PrecisionRecallEvaluator.PRResult;

public class ROCEvaluator {

	ArrayList<PRResult> results = new ArrayList<>();

	public String param = StringResources.STR_EMPTY;
	public String dataset = StringResources.STR_EMPTY;

	private ROCConfusion confusion = null;

	public ROCEvaluator(String param, String dataset) {
		this.param = param;
		this.dataset = dataset;
	}

	public void feed(PRResult result) {
		results.add(result);
	}

	public void feed(List<PRResult> results) {
		this.results.addAll(results);
	}

	public void feed(PRResult... results) {
		feed(Arrays.asList(results));
	}

	private void constructConfusion() {
		PRResult allResult = PRResult.check(results);
		confusion = new ROCConfusion(allResult.size_truth,
				allResult.size_total_space - allResult.size_truth);
		for (PRResult result : results) {
			confusion.addPRPoint(result.calRecall(), result.calPrecision());
		}
		confusion.sort();
		confusion.interpolate();
	}

	public double[][] toPRCurve() {
		if (confusion == null)
			constructConfusion();
		return confusion.getSPR();
	}

	public double[][] toROCCurve() {
		if (confusion == null)
			constructConfusion();
		return confusion.getROC();
	}

	public double calAreaUnderPR(double minRecall) {
		if (confusion == null)
			constructConfusion();
		return confusion.calculateAUCPR(minRecall);
	}

	public double calAreaUnderROC() {
		if (confusion == null)
			constructConfusion();
		return confusion.calculateAUCROC();
	}

}
