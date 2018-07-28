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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.heap.Ranker;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import scala.Tuple2;
import scala.Tuple3;

public class ScoringUnit implements Serializable {

	// private static Logger logger = LoggerFactory.getLogger(ScoringUnit.class);

	private static final long serialVersionUID = -6521055215034904582L;
	// srcfid -> srcFSU
	public HashMap<Long, F_ScoringUnit> candidates = new HashMap<>();

	private long fidToAvoid;

	public ScoringUnit(long fidToAvoid) {
		this.fidToAvoid = fidToAvoid;
	}

	public void add(String varName, Block tar, IOEntry entry, double normalizer) {

		Long srcFid = entry.functionId;
		Long srcBid = entry.blockId;
		Long tarBid = tar.blockId;
		int funcSize = entry.funcSize;
		double score = 1.0 / normalizer;

		if (srcFid.equals(fidToAvoid))
			return;

		B_ScoringUnit bu = candidates.compute(srcFid, (k, v) -> v == null ? new F_ScoringUnit(srcFid, funcSize) : v).map
				.compute(tarBid, (k, v) -> v == null ? new B_ScoringUnit(tar) : v);

		bu.candidates.compute(srcBid, (k, v) -> v == null ? new TB_ScoringUnit(entry.calls, srcBid) : v).varMap
				.compute(varName, (k, v) -> v == null ? score : Math.max(v, score));
	}

	public List<F_ScoringUnit> getTopK(int topK) {
		Ranker<F_ScoringUnit> ranking = new Ranker<>(topK);
		candidates.forEach((k, v) -> {
			F_ScoringUnit fu = v;
			fu.calculateScore1();
			ranking.push(fu.score, fu);
		});
		return ranking.sortedList(false);
	}

	/**
	 * Scoring a set of variables.
	 * 
	 * @author dingm
	 *
	 */
	public static class TB_ScoringUnit {
		public Long srcbid;
		public List<Long> calls;
		public double score;
		public HashMap<String, Double> varMap = new HashMap<>();

		public TB_ScoringUnit(List<Long> calls, Long srcbid) {
			this.calls = calls;
			this.srcbid = srcbid;
		}

		public void calculateScore() {
			score = varMap.values().stream().mapToDouble(val -> val).sum();
		}
	}

	public static class B_ScoringUnit {
		public Block tar;

		public String toString(long rid, AsmObjectFactory factory) {
			StringBuilder builder = new StringBuilder();
			builder.append(tar.blockName);
			builder.append("[");
			candidates.values().stream().forEach(tbu -> {
				String tarName = factory.obj_blocks.querySingle(rid, tbu.srcbid).blockName;
				builder.append(tarName + "::" + StringResources.FORMAT_AR5D.format(tbu.score));
				builder.append(",");
			});
			builder.append("]");
			return builder.toString();
		}

		/**
		 * srcbbid -> (varname-> (entry, normalizer))
		 */
		public HashMap<Long, TB_ScoringUnit> candidates = new HashMap<>();

		public void calculateScore() {
			candidates.values().forEach(TB_ScoringUnit::calculateScore);

			// pick top k:
			// Heap<TB_ScoringUnit> rank = new Heap<>(3);
			// candidates.values().stream().forEach(cand ->
			// rank.push(cand.score, cand));
			// Set<Long> vids = rank.getKeys().stream().map(tb ->
			// tb.srcbid).collect(Collectors.toSet());
			// candidates.keySet().removeIf(key -> !vids.contains(key));
		}

		public B_ScoringUnit(Block tar) {
			this.tar = tar;
		}

	}

	public static class F_ScoringUnit {
		public double score = 0;
		public double graphScore = 0;
		public double cScore = 0;
		public long srcfid;
		public int funcSize;

		// tar-> tar_SCU
		public HashMap<Long, B_ScoringUnit> map = new HashMap<>();

		public F_ScoringUnit(long srcfid, int funcSize) {
			this.srcfid = srcfid;
			this.funcSize = funcSize;
		}

		public void calculateScore2() {
			map.values().forEach(B_ScoringUnit::calculateScore);
			HashSet<Tuple2<Long, Long>> covered = new HashSet<>();
			this.score = 0;
			map.values().forEach(v -> {
				Block tarb = v.tar;
				B_ScoringUnit candidateScores = v;
				tarb.callingBlocks.forEach(calleeId -> {
					double pairScore = 0;
					Tuple2<Long, Long> maxPair = null;
					B_ScoringUnit candidateScoresCallee = map.get(calleeId);
					if (candidateScoresCallee != null)
						for (Entry<Long, TB_ScoringUnit> ent : candidateScores.candidates.entrySet()) {
							TB_ScoringUnit candidateScoringUnit = ent.getValue();
							List<Long> candidateCalls = candidateScoringUnit.calls;
							for (Long candidateCall : candidateCalls) {
								TB_ScoringUnit calleeScoringUnit = candidateScoresCallee.candidates.get(candidateCall);
								if (calleeScoringUnit != null) {
									Tuple2<Long, Long> srcLink = new Tuple2<>(ent.getKey(), candidateCall);
									if (!covered.contains(srcLink)) {
										double newScore = calleeScoringUnit.score + candidateScoringUnit.score;
										if (newScore > pairScore) {
											pairScore = newScore;
											maxPair = srcLink;
										}
									}
								}
							}
						}
					if (maxPair != null)
						covered.add(maxPair);
					graphScore += pairScore;
				});
				this.score += candidateScores.candidates.values().stream().mapToDouble(unit -> unit.score).max()
						.getAsDouble();
			});

			this.score += graphScore;
			this.score /= Math.sqrt(funcSize);
			this.score += cScore;
		}

		public void calculateScore1() {
			map.values().forEach(B_ScoringUnit::calculateScore);
			this.score = 0;
			map.values().forEach(v -> {
				Block tarb = v.tar;
				B_ScoringUnit candidateScores = v;
				tarb.callingBlocks.forEach(calleeId -> {
					double pairScore = 0;
					B_ScoringUnit candidateScoresCallee = map.get(calleeId);
					if (candidateScoresCallee != null)
						for (Entry<Long, TB_ScoringUnit> ent : candidateScores.candidates.entrySet()) {
							TB_ScoringUnit candidateScoringUnit = ent.getValue();
							List<Long> candidateCalls = candidateScoringUnit.calls;
							for (Long candidateCall : candidateCalls) {
								TB_ScoringUnit calleeScoringUnit = candidateScoresCallee.candidates.get(candidateCall);
								if (calleeScoringUnit != null)
									pairScore = Math.max(pairScore,
											calleeScoringUnit.score + candidateScoringUnit.score);
							}
						}
					graphScore += pairScore;
				});
				this.score += candidateScores.candidates.values().stream().mapToDouble(unit -> unit.score).max()
						.getAsDouble();
			});

			this.score += graphScore;
			this.score /= Math.sqrt(funcSize);
		}

		public void calculateScore() {
			map.values().forEach(B_ScoringUnit::calculateScore);
			map.values().forEach(v -> {
				// Block tarb = v.tar.block;
				B_ScoringUnit candidateScores = v;
				this.score += candidateScores.candidates.values().stream().mapToDouble(unit -> unit.score).max()
						.getAsDouble();
			});

			this.score /= Math.sqrt(funcSize);
		}

		public List<Tuple3<Long, Block, Double>> toSrcBbIdTarScorePairs() {
			return map.values().stream().flatMap(
					bu -> bu.candidates.values().stream().map(cand -> new Tuple3<>(cand.srcbid, bu.tar, cand.score)))
					.collect(Collectors.toList());
		}

	}
}
