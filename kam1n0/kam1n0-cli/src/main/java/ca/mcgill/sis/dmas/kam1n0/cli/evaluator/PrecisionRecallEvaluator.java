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

import gnu.trove.set.hash.TLongHashSet;

import java.util.ArrayList;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectionResultForCLI;

public class PrecisionRecallEvaluator {

	private static Logger logger = LoggerFactory.getLogger(PrecisionRecallEvaluator.class);

	public static class PRResult {

		public static PRResult merge(String param, Iterable<PRResult> results) {
			PRResult result = new PRResult();
			result.params = param;
			for (PRResult prResult : results) {
				result.hit += prResult.hit;
				result.size_answers += prResult.size_answers;
				result.size_truth += prResult.size_truth;
				result.size_total_space += prResult.size_total_space;
			}
			return result;
		}

		public static PRResult check(Iterable<PRResult> results) {
			PRResult result = new PRResult();
			Long size_truth = null;
			Long size_total_space = null;
			boolean valid = true;
			for (PRResult prResult : results) {
				if (size_truth == null)
					size_truth = prResult.size_truth;
				if (size_total_space == null)
					size_total_space = prResult.size_total_space;
				if (size_truth != prResult.size_truth || size_total_space != prResult.size_total_space) {
					valid = false;
					break;
				}
			}

			if (valid) {
				result.size_truth = size_truth;
				result.size_total_space = size_total_space;
				return result;
			} else {
				logger.error("Invalid sequence of test result on same data. ");
				return null;
			}
		}

		public int hit = 0;
		public long size_answers = 0;
		public long size_truth = 0;
		public long size_total_space = 0;

		public double precision = -1;
		public double recall = -1;
		public double f1 = -1;

		public double calPrecision() {
			if (precision != -1)
				return precision;
			if (size_answers != 0) {
				precision = hit * 1.0 / size_answers;
				return precision;
			} else
				return 1;
		}

		public double calRecall() {
			if (recall != -1)
				return recall;
			if (size_truth == 0)
				return 1;
			else {
				recall = hit * 1.0 / size_truth;
				return recall;
			}
		}

		public double calF1() {
			if (f1 != -1)
				return f1;
			double recall = calRecall();
			double precision = calPrecision();
			if (precision + recall != 0) {
				f1 = 2 * (precision * recall) / (precision + recall);
				return f1;
			} else
				return 0;
		}

		public long calP() {
			return size_truth;
		}

		public long calN() {
			return size_total_space - size_truth;
		}

		public String dataset = StringResources.STR_EMPTY;
		public String params = StringResources.STR_EMPTY;

		@Override
		public String toString() {
			return StringResources.JOINER_TOKEN_CSV.join("param:", params, "dataset:", dataset, "precision:",
					StringResources.FORMAT_AR5D.format(calPrecision()), "recall:",
					StringResources.FORMAT_AR5D.format(calRecall()), "f1:",
					StringResources.FORMAT_AR5D.format(calF1()));
		}
	}

	public static class PRResultDetails extends PRResult {
		public ArrayList<EntryTriplet<Long, Long, Double>> falsePositives = new ArrayList<>();
		public ArrayList<EntryTriplet<Long, Long, Double>> falseNegatives = new ArrayList<>();
	}

	public static PRResult evaluate(String params, TLongHashSet searchSpace,
			ArrayList<EntryTriplet<Long, Long, Double>> truth, double thresholdForTruths,
			ArrayList<EntryTriplet<Long, Long, Double>> answer) {
		PRResult result = new PRResult();

		HashSet<String> truthSet = new HashSet<>();
		for (EntryTriplet<Long, Long, Double> truthEntry : truth) {
			if (!searchSpace.contains(truthEntry.value0) || !searchSpace.contains(truthEntry.value1)) {
				continue;
			}
			if (truthEntry.value2 < thresholdForTruths)
				continue;
			String pair;
			if (truthEntry.value0 < truthEntry.value1) {
				pair = truthEntry.value0 + "," + truthEntry.value1;
			} else {
				pair = truthEntry.value1 + "," + truthEntry.value0;
			}
			truthSet.add(pair);
		}

		int hit = 0;
		for (EntryTriplet<Long, Long, Double> answerEntry : answer) {
			if (!searchSpace.contains(answerEntry.value0) || !searchSpace.contains(answerEntry.value1)) {
				logger.error("should not reach here; found a answer that is not part of question {}, {}",
						answerEntry.value0, answerEntry.value1);
				continue;
			}
			String pair;
			if (answerEntry.value0 < answerEntry.value1) {
				pair = answerEntry.value0 + "," + answerEntry.value1;
			} else {
				pair = answerEntry.value1 + "," + answerEntry.value0;
			}
			if (truthSet.contains(pair))
				hit++;
		}

		result.hit = hit;
		result.size_answers = answer.size();
		result.size_truth = truthSet.size();
		result.params = params;
		result.size_total_space = searchSpace.size();

		return result;
	}

	public static PRResultDetails evaluateDetails(String params, FunctionCloneDetectionResultForCLI truth, double thresholdForTruths,
			FunctionCloneDetectionResultForCLI answer) {

		PRResultDetails result = new PRResultDetails();
		HashSet<Long> searchSpace = answer.searchSpaceVals;

		HashSet<String> answerSet = new HashSet<>();
		for (EntryTriplet<Long, Long, Double> answerEntry : answer.cloneMape) {
			if (answerEntry.value2 < thresholdForTruths)
				continue;
			String pair;
			if (answerEntry.value0 < answerEntry.value1) {
				pair = answerEntry.value0 + "," + answerEntry.value1;
			} else {
				pair = answerEntry.value1 + "," + answerEntry.value0;
			}
			answerSet.add(pair);
		}

		HashSet<String> truthSet = new HashSet<>();
		for (EntryTriplet<Long, Long, Double> truthEntry : truth.cloneMape) {
			if (!searchSpace.contains(truthEntry.value0) || !searchSpace.contains(truthEntry.value1)) {
				continue;
			}
			if (truthEntry.value2 < thresholdForTruths)
				continue;
			String pair;
			if (truthEntry.value0 < truthEntry.value1) {
				pair = truthEntry.value0 + "," + truthEntry.value1;
			} else {
				pair = truthEntry.value1 + "," + truthEntry.value0;
			}
			truthSet.add(pair);
			if (!answerSet.contains(pair)) {
				result.falseNegatives.add(truthEntry);
			}
		}

		int hit = 0;
		for (EntryTriplet<Long, Long, Double> answerEntry : answer.cloneMape) {
			String pair;
			if (answerEntry.value0 < answerEntry.value1) {
				pair = answerEntry.value0 + "," + answerEntry.value1;
			} else {
				pair = answerEntry.value1 + "," + answerEntry.value0;
			}
			if (truthSet.contains(pair))
				hit++;
			else
				result.falsePositives.add(answerEntry);
		}

		result.hit = hit;
		result.size_answers = answer.cloneMape.size();
		result.size_truth = truthSet.size();
		result.params = params;
		result.size_total_space = searchSpace.size();

		return result;
	}
}
