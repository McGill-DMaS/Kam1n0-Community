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

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import auc.Confusion;
import auc.ReadList;
import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectionResultForCLI;

public class AnswerWrapperROCEvaluator extends AnswerWrapperEvaluator {

	private static Logger logger = LoggerFactory.getLogger(AnswerWrapperROCEvaluator.class);

	public static class ROCResult {
		public double AUCROC = 0;
		public double AUCPR = 0;
		public double BestF1 = 0;
		public double BestF2 = 0;
	}

	FunctionCloneDetectionResultForCLI truths;
	double thresholdForTruth;

	public AnswerWrapperROCEvaluator(FunctionCloneDetectionResultForCLI truths, double thresholdForTruth) {
		this.truths = truths;
		this.thresholdForTruth = thresholdForTruth;
	}

	public List<Double> evaluate(FunctionCloneDetectionResultForCLI answers) throws Exception {
		File listFile = DmasApplication.createTmpFile(truths.caseName + "-" + StringResources.randomString(5) + ".txt");
		LineSequenceWriter writer = Lines.getLineWriter(listFile.getAbsolutePath(), false);

		logger.info("reading truths...");
		HashMap<EntryPair<Long, Long>, Integer> truthSheet = new HashMap<>();
		for (EntryTriplet<Long, Long, Double> clone : truths.cloneMape) {

			EntryPair<Long, Long> key;
			if (clone.value0.equals(clone.value1))
				continue;
			if (clone.value0 < clone.value1)
				key = new EntryPair<Long, Long>(clone.value0, clone.value1);
			else
				key = new EntryPair<Long, Long>(clone.value1, clone.value0);
			if (clone.value2 >= thresholdForTruth)
				truthSheet.put(key, 1);
			else
				truthSheet.put(key, 0);
		}

		logger.info("reading answers...");
		HashMap<EntryPair<Long, Long>, Double> answerSheet = new HashMap<>();
		answers.cloneMape.forEach(answer -> {
			EntryPair<Long, Long> key;
			if (answer.value0.equals(answer.value1))
				return;
			if (answer.value0 < answer.value1)
				key = new EntryPair<Long, Long>(answer.value0, answer.value1);
			else
				key = new EntryPair<Long, Long>(answer.value1, answer.value0);
			answerSheet.put(key, answer.value2);
		});

		logger.info("generating answer sheet...");
		for (Long sid : answers.searchSpaceVals) {
			for (Long tid : answers.searchSpaceVals) {
				if (sid != tid) {
					EntryPair<Long, Long> key;
					if (sid < tid)
						key = new EntryPair<Long, Long>(sid, tid);
					else
						key = new EntryPair<Long, Long>(tid, sid);
					Double score = answerSheet.get(key);
					Integer truth = truthSheet.get(key);
					if (score == null)
						score = 0.0;
					if (score > 1.0)
						score = 1.0;
					if (score < 0.0)
						score = 0.0;
					if (truth == null)
						truth = 0;
					try {
						writer.writeLine(score + " " + truth);
					} catch (Exception e) {
						logger.info("Failed to write to output tmp file..", e);
						return null;
					}
				}
			}
		}
		writer.close();

		logger.info("Interpolating...");
		ROCConfusion confusion = ROCReadList.readFile(listFile.getAbsolutePath(), "list");

		logger.info("Calculating...");

		ROCResult result = new ROCResult();
		result.AUCPR = confusion.calculateAUCPR(0);
		result.AUCROC = confusion.calculateAUCROC();

		result.BestF1 = -1;
		result.BestF2 = -1;
		for (double[] rp : confusion.getPR()) {
			double f1 = 2 * rp[0] * rp[1] / (rp[0] + rp[1]);
			result.BestF1 = Math.max(f1, result.BestF1);
			double f2 = 5 * rp[0] * rp[1] / (4 * rp[0] + rp[1]);
			result.BestF2 = Math.max(f2, result.BestF2);
		}

		return Arrays.asList(result.AUCROC);
	}

	public static void main(String[] args) throws Exception {

		Environment.init();

		String mrPath = "E:\\kam1no\\MRresult\\libtiff.txt";
		String ansPath = "E:\\kam1no\\MRresult-baseline\\DetectorNperm\\libtiff.txt";
		String truthPath = "E:\\kam1no\\kam1n0-debugSymbol\\libtiff\\mclones.txt";

		FunctionCloneDetectionResultForCLI aw = FunctionCloneDetectionResultForCLI.load(mrPath);
		FunctionCloneDetectionResultForCLI truths = FunctionCloneDetectionResultForCLI.load(truthPath);

		AnswerWrapperROCEvaluator evaluator = new AnswerWrapperROCEvaluator(truths, .3999);

		// ROCResult rsl = evaluator.evaluate(aw);
		//
		// logger.info("AUCROC: {}", rsl.AUCROC);
		// logger.info("AUCPR: {}", rsl.AUCPR);
		// logger.info("Best F1 {}", rsl.BestF1);
	}

	@Override
	public String metricName() {
		return "ROC";
	}
}
