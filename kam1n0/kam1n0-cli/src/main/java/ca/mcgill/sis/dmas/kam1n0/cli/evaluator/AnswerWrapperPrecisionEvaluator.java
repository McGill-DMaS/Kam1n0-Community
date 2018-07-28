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
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.io.collection.heap.DuplicatedRanker;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectionResultForCLI;
import scala.Tuple2;

public class AnswerWrapperPrecisionEvaluator extends AnswerWrapperEvaluator {

	private static Logger logger = LoggerFactory.getLogger(AnswerWrapperPrecisionEvaluator.class);

	private FunctionCloneDetectionResultForCLI truths;
	private double thresholdForTruth;

	private int topKEnd;
	private int topKStart;
	private int topKInterval;

	public AnswerWrapperPrecisionEvaluator(FunctionCloneDetectionResultForCLI truths, double thresholdForTruth) {
		this.truths = truths;
		this.thresholdForTruth = thresholdForTruth;
	}

	public AnswerWrapperPrecisionEvaluator(FunctionCloneDetectionResultForCLI truths, double thresholdForTruth,
			int topK) {
		this.truths = truths;
		this.thresholdForTruth = thresholdForTruth;
		this.topKStart = topK;
		this.topKEnd = topK + 1;
		this.topKInterval = 1;
	}

	public AnswerWrapperPrecisionEvaluator(FunctionCloneDetectionResultForCLI truths, double thresholdForTruth,
			int topKStart, int topKEnd, int interval) {
		this.truths = truths;
		this.thresholdForTruth = thresholdForTruth;
		this.topKStart = topKStart;
		this.topKEnd = topKEnd;
		this.topKInterval = interval;
	}

	public List<Double> evaluate(FunctionCloneDetectionResultForCLI answers) throws Exception {

		Map<Long, String> map = this.generateIdNameMapping(answers);

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
		answerSheet.keys().parallelStream().map(key -> answerSheet.get(key))
				.forEach(ls -> ls.sort((o1, o2) -> o2._2.compareTo(o1._2)));

		logger.info("testing...");
		// double map = 0;
		// int total = 0;
		// for (Long need : answers.querySpaceVals) {
		List<Double> scores = new ArrayList<>();
		for (int kval = topKStart; kval < topKEnd; kval += topKInterval) {
			int n = kval;
			double score = answers.querySpaceVals.parallelStream().map(query -> {
				Set<Long> needs = new HashSet<>(
						Sets.intersection(answers.searchSpaceVals, new HashSet<>(infoNeeds.get(query))));
				if (needs.size() == 0) {
					// logger.info("no needs for {}", map.get(need));
					return null;
				}
				// total++;
				List<Tuple2<Long, Double>> provides = answerSheet.get(query);
				// if (provides.size() == 0) {
				// logger.info("query {} needs {} provides {}", map.get(query),
				// needs.stream().map(nd ->
				// map.get(nd)).collect(Collectors.toList()),
				// provides.stream().map(tp ->
				// map.get(tp._1)).collect(Collectors.toList()));
				//
				// return new Double(0);
				// }
				int size = needs.size() < n ? needs.size() : n;
				// Heap<Long> provides_heap = new Heap<>(size);
				// provides.stream().forEach(tp -> provides_heap.push(tp._2,
				// tp._1));
				DuplicatedRanker<Long> ranker = new DuplicatedRanker<>(size);
				provides.stream().forEach(tp -> ranker.push(tp._2, tp._1));

				double numbOfProvidersAreCorrect = Sets.intersection(ranker.valueSet(), needs).size();
				if (numbOfProvidersAreCorrect > n)
					numbOfProvidersAreCorrect = n;

				// if (numbOfProvidersAreCorrect == 0) {
				// Set<Long> ps = provides.stream().map(tp ->
				// tp._1).collect(Collectors.toSet());
				// if (Sets.intersection(ps, needs).size() > 0) {
				// System.out.println("- - - - - - - - - - - - -");
				// System.out.println("Query: " + map.get(query));
				// System.out.println(
				// "Needs: " + needs.stream().map(nd ->
				// map.get(nd)).collect(Collectors.toList()));
				// for (Tuple2<Long, Double> p : provides) {
				// if (needs.contains(p._1)) {
				// System.out.println(
				// " * " + StringResources.FORMAT_AR4D.format(p._2) + " " +
				// map.get(p._1));
				// break;
				// } else
				// System.out
				// .println(" " + StringResources.FORMAT_AR4D.format(p._2) + " "
				// + map.get(p._1));
				// }
				// }
				// }
				return new Double(numbOfProvidersAreCorrect * 1.0 / n);
			}).filter(val -> val != null).mapToDouble(val -> val).average().getAsDouble();
			// double score = map / total;
			logger.info("P@{} {}", n, StringResources.FORMAT_AR5D.format(score));
			scores.add(score);
		}
		return scores;

	}

	@Override
	public String metricName() {
		if (this.topKStart == this.topKEnd - this.topKInterval)
			return "Precision@" + this.topKStart;
		else
			return "Precision@" + this.topKStart + "-" + this.topKEnd;
	}

}
