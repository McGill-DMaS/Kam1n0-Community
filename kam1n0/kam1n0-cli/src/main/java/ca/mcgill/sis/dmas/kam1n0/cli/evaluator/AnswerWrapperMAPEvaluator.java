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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectionResultForCLI;
import scala.Tuple2;

public class AnswerWrapperMAPEvaluator extends AnswerWrapperEvaluator {

	private static Logger logger = LoggerFactory.getLogger(AnswerWrapperMAPEvaluator.class);

	private FunctionCloneDetectionResultForCLI truths;
	private double thresholdForTruth;
	private int topKEnd;
	private int topKStart;
	private int topKInterval;

	public AnswerWrapperMAPEvaluator(FunctionCloneDetectionResultForCLI truths, double thresholdForTruth, int topK) {
		this.truths = truths;
		this.thresholdForTruth = thresholdForTruth;
		this.topKStart = topK;
		this.topKEnd = topK + 1;
		this.topKInterval = 1;
	}

	public AnswerWrapperMAPEvaluator(FunctionCloneDetectionResultForCLI truths, double thresholdForTruth, int topKStart,
			int topKEnd, int interval) {
		this.truths = truths;
		this.thresholdForTruth = thresholdForTruth;
		this.topKStart = topKStart;
		this.topKEnd = topKEnd;
		this.topKInterval = interval;
	}

	public List<Double> evaluate(FunctionCloneDetectionResultForCLI answers) throws Exception {

		logger.info("reading truths...");
		HashMultimap<Long, Long> infoNeeds = HashMultimap.create();
		for (EntryTriplet<Long, Long, Double> clone : truths.cloneMape) {
			if (clone.value0.equals(clone.value1))
				continue;
			if (clone.value2 >= thresholdForTruth) {
				infoNeeds.put(clone.value0, clone.value1);
			}
		}

		logger.info("reading answers...");
		ListMultimap<Long, Tuple2<Long, Double>> answerSheet = ArrayListMultimap.create();
		for (EntryTriplet<Long, Long, Double> clone : answers.cloneMape) {
			if (clone.value0.equals(clone.value1))
				continue;
			answerSheet.put(clone.value0, new Tuple2<>(clone.value1, clone.value2));
		}
		logger.info("sorting ...");
		answerSheet.keys().stream().parallel().map(key -> answerSheet.get(key))
				.forEach(ls -> ls.sort((o1, o2) -> o2._2.compareTo(o1._2)));

		logger.info("testing...");
		List<Double> scores = new ArrayList<>();
		for (int kval = topKStart; kval < topKEnd; kval += topKInterval) {
			int m = kval;
			double map = 0;
			int total = 0;
			for (Long need : answers.querySpaceVals) {
				Set<Long> needs = new HashSet<>(
						Sets.intersection(answers.searchSpaceVals, new HashSet<>(infoNeeds.get(need))));
				if (needs.size() == 0)
					continue;
				List<Tuple2<Long, Double>> provides = answerSheet.get(need);
				int divier = Math.min(needs.size(), m);
				double ap = 0;
				int hit = 0;
				for (int i = 0; i < Math.min(divier, provides.size()); ++i) {
					Tuple2<Long, Double> answerAtI = provides.get(i);
					if (needs.contains(answerAtI._1)) {
						hit++;
						ap += hit * 1.0 / (i + 1);
						needs.remove(answerAtI._1);
					}
				}
				map += ap / divier;
				total++;
			}
			double score = map / total;
			scores.add(score);
			logger.info("MAP@{} {}", m, StringResources.FORMAT_AR5D.format(score));
		}
		return scores;
	}

	@Override
	public String metricName() {
		if (this.topKStart == this.topKEnd - this.topKInterval)
			return "MAP@" + this.topKStart;
		else
			return "MAP@" + this.topKStart + "-" + this.topKEnd;
	}

}
