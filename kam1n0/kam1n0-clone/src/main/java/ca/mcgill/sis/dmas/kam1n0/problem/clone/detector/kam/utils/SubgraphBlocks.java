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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import scala.Tuple2;
import scala.Tuple3;

public class SubgraphBlocks implements Serializable {

	private static final long serialVersionUID = -2343845285400479014L;

	public static class Subgraph {
		public HashSet<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> links = new HashSet<>();
		public Double score = 0d;

		public Set<Long> tarCoverage() {
			return links.stream().map(tp3 -> tp3._1().original.blockId).collect(Collectors.toSet());
		}

		public Set<Long> srcCoverage() {
			return links.stream().map(tp3 -> tp3._2().original.blockId).collect(Collectors.toSet());
		}

		@Override
		public String toString() {
			return tarCoverage().size() + "-" + srcCoverage().size() + "/" + links.size() + ":"
					+ StringResources.FORMAT_AR4D.format(score);
		}

		public double cal() {
			double s1 = tarCoverage().size();
			double s2 = srcCoverage().size();
			return s1 - Math.abs(s1 - s2);
		}
	}

	// (tar, src, score)
	public ArrayList<Subgraph> subgraphs = new ArrayList<>();
	public ArrayList<HashSet<Tuple2<HashedLinkedBlock, HashedLinkedBlock>>> subgraphs_old = new ArrayList<>();

	public static class HashedLinkedBlock implements Serializable {
		private static final long serialVersionUID = 2001766346831055102L;

		public HashSet<Long> links;

		public Block original;

		public HashedLinkedBlock(Block block) {
			this.original = block;
			links = new HashSet<>(block.callingBlocks);
		}

		@Override
		public String toString() {
			return original.blockName;
		}

		@Override
		public int hashCode() {
			return original.hashCode();
		}
	}

	public static <T> T pick(Collection<T> collection) {
		if (collection.size() == 0)
			return null;
		for (T t : collection) {
			return t;
		}
		return null;
	}

	public static FunctionCloneEntry mergeSingles(Set<Long> tarbids,
			Iterable<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> pairs) {

		FunctionCloneEntry entry = new FunctionCloneEntry();

		int count = Iterables.size(pairs);
		if (count == 0)
			return null;
		Block block = Iterables.getFirst(pairs, null)._2().original;
		/**
		 * Generate subgraphs:
		 */

		SubgraphBlocks result = new SubgraphBlocks();

		HashMultimap<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>, Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> mergableMap = HashMultimap
				.create();

		pairs.forEach(p1 -> {
			pairs.forEach(p2 -> {
				if (compare(p1, p2)) {
					mergableMap.put(p1, p2);
					mergableMap.put(p2, p1);
				}
			});
		});

		pairs.forEach(p1 -> {
			if (!mergableMap.containsKey(p1)) {
				Subgraph singular = new Subgraph();
				singular.links.add(p1);
				singular.score = p1._3();
				result.subgraphs.add(singular);
			}
		});

		// if (debugLevel > 0)
		// entry.logs.add(StringResources.format("Candidate {}:{} {} pairs {}
		// entries to be merged.",
		// block.functionName, binaryName, count, mergableMap.size()));

		while (mergableMap.size() != 0) {
			Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> seed = pick(mergableMap.keySet());
			HashSet<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> stack = new HashSet<>();
			HashSet<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> stack_finished = new HashSet<>();
			stack.add(seed);
			while (stack.size() != 0) {
				Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> tp = pick(stack);
				stack.addAll(mergableMap.get(tp));
				stack.remove(tp);
				mergableMap.removeAll(tp);
				stack_finished.add(tp);
			}
			if (stack_finished.size() != 0) {
				Subgraph subgraph = new Subgraph();
				subgraph.links = stack_finished;
				subgraph.score = subgraph.links.stream().mapToDouble(lnk -> lnk._3()).sum();
				result.subgraphs.add(subgraph);
			}
		}

		// sorted according to graph score
		result.subgraphs.sort((sub1, sub2) -> Integer.compare(sub2.tarCoverage().size(), sub1.tarCoverage().size()));

		// let's calculate similarity:
		double score = 0;
		HashSet<Long> coveredTarbids = new HashSet<>();
		HashSet<Long> coveredSrcbids = new HashSet<>();
		// links : (tar, src, score)

		// if (debugLevel > 1)
		// entry.logs.add(StringResources.format("Candidate {}:{}. Score {}.
		// Covered tarbids: {}; Covered srcbids: {}",
		// block.functionName, binaryName, score, coveredTarbids,
		// coveredSrcbids));

		for (Subgraph subgraph : result.subgraphs) {
			double subScore = subgraph.links.stream().filter(lnk -> {
				long tarbid = lnk._1().original.blockId;
				long srcbid = lnk._2().original.blockId;
				boolean coveredTar = coveredTarbids.contains(tarbid);
				boolean coveredSrc = coveredSrcbids.contains(srcbid);
				boolean canBeUsed = !coveredTar && !coveredSrc;
				if (canBeUsed) {
					coveredTarbids.add(tarbid);
					coveredSrcbids.add(srcbid);
				}
				return canBeUsed;
			}).mapToDouble(lnk -> lnk._3()).sum();
			score += subScore;

		}

		entry.functionId = block.functionId;
		entry.functionName = block.functionName;
		entry.binaryId = block.binaryId;
		entry.binaryName = block.binaryName;
		result.subgraphs.forEach(set -> {
			HashSet<Tuple3<Long, Long, Double>> nset = new HashSet<>();
			set.links.forEach(tp -> nset
					.add(new Tuple3<Long, Long, Double>(tp._1().original.blockId, tp._2().original.blockId, tp._3())));
			entry.clonedParts.add(nset);
		});

		Block aBlock = result.subgraphs.get(0).links.stream().findAny().get()._2().original;

		entry.similarity = score;

		return entry;

	}

	public static FunctionCloneEntry mergeSinglesOld(
			Iterable<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> pairs, HashSet<Tuple2<Long, Long>> links,
			int totalNodes, int funcLength) {
		SubgraphBlocks result = new SubgraphBlocks();
		HashSet<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> unique_pairs = Sets.newHashSet(pairs);

		while (unique_pairs.size() != 0) {
			Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> taken = unique_pairs.stream().findAny().get();
			unique_pairs.remove(taken);
			ArrayList<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> subgraph = new ArrayList<>();
			subgraph.add(taken);
			int ind = 0;
			while (ind < subgraph.size()) {
				Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> tar = subgraph.get(ind);
				HashSet<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> used = new HashSet<>();
				// avoid blocking
				ForkJoinPool pool = new ForkJoinPool(3);
				try {
					pool.submit(() -> {
						unique_pairs.parallelStream().forEach(src -> {
							if (compare(tar, src)) {
								synchronized (subgraph) {
									subgraph.add(tar);
									subgraph.add(src);
									used.add(tar);
									used.add(src);
								}
							}
						});
					}).get();
					pool.shutdownNow();
				} catch (Exception e) {

				}
				unique_pairs.removeAll(used);
				ind++;
			}
			Subgraph subg = new Subgraph();
			subg.links = new HashSet<>(subgraph);
			result.subgraphs.add(subg);
		}

		FunctionCloneEntry entry = new FunctionCloneEntry();
		Block block = result.subgraphs.get(0).links.stream().findAny().get()._2().original;
		entry.functionId = block.functionId;
		entry.functionName = block.functionName;
		entry.binaryId = block.binaryId;
		entry.binaryName = block.binaryName;
		result.subgraphs.forEach(subg -> {
			HashSet<Tuple3<Long, Long, Double>> nset = new HashSet<>();
			subg.links
					.forEach(tp -> nset.add(new Tuple3<>(tp._1().original.blockId, tp._2().original.blockId, tp._3())));
			entry.clonedParts.add(nset);
		});

		HashSet<Tuple2<Long, Long>> clonedLinks = new HashSet<>();
		for (Subgraph hashSet : result.subgraphs) {
			for (Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> tuple2 : hashSet.links) {
				for (Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> tuple3 : hashSet.links) {
					clonedLinks.add(new Tuple2<Long, Long>(tuple2._1().original.blockId, tuple3._1().original.blockId));
				}
			}
		}
		clonedLinks.retainAll(links);
		double node_coverage = clonedLinks.stream().filter(tp -> tp._1.equals(tp._2)).count();
		double link_coverage = clonedLinks.size() - node_coverage;
		entry.similarity = (link_coverage * totalNodes + node_coverage) * 1.0
				/ ((links.size() - totalNodes) * totalNodes + totalNodes);
		return entry;

	}

	public static SubgraphBlocks mergeSingles(Iterable<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> pairs3) {
		List<Tuple2<HashedLinkedBlock, HashedLinkedBlock>> pairs = StreamSupport.stream(pairs3.spliterator(), false)
				.map(tp3 -> new Tuple2<HashedLinkedBlock, HashedLinkedBlock>(tp3._1(), tp3._2()))
				.collect(Collectors.toList());
		SubgraphBlocks result = new SubgraphBlocks();
		HashSet<Tuple2<HashedLinkedBlock, HashedLinkedBlock>> unique_pairs = Sets.newHashSet(pairs);
		int total = unique_pairs.size();

		while (unique_pairs.size() != 0) {
			Tuple2<HashedLinkedBlock, HashedLinkedBlock> taken = unique_pairs.stream().findAny().get();
			unique_pairs.remove(taken);
			ArrayList<Tuple2<HashedLinkedBlock, HashedLinkedBlock>> subgraph = new ArrayList<>();
			subgraph.add(taken);
			int ind = 0;
			while (ind < subgraph.size()) {
				Tuple2<HashedLinkedBlock, HashedLinkedBlock> tar = subgraph.get(ind);
				HashSet<Tuple2<HashedLinkedBlock, HashedLinkedBlock>> used = new HashSet<>();
				// avoid blocking
				ForkJoinPool pool = new ForkJoinPool(3);
				try {
					pool.submit(() -> {
						unique_pairs.parallelStream().forEach(src -> {
							if (compare(tar, src)) {
								synchronized (subgraph) {
									subgraph.add(tar);
									subgraph.add(src);
									used.add(tar);
									used.add(src);
								}
							}
						});
					}).get();
					pool.shutdownNow();
				} catch (Exception e) {

				}
				unique_pairs.removeAll(used);
				ind++;
			}
			result.subgraphs_old.add(new HashSet<>(subgraph));
			// System.out.println(subgraph.size() + "/" + unique_pairs.size() +
			// "/" + total);
		}

		return result;
	}

	public FunctionCloneEntry toFunctionCloneEntry(int funcLength) {
		FunctionCloneEntry entry = new FunctionCloneEntry();
		Block block = subgraphs_old.get(0).stream().findAny().get()._2.original;
		entry.functionId = block.functionId;
		entry.functionName = block.functionName;
		entry.binaryId = block.binaryId;
		entry.binaryName = block.binaryName;
		this.subgraphs_old.forEach(set -> {
			HashSet<Tuple2<Long, Long>> nset = new HashSet<>();
			set.forEach(tp -> nset.add(new Tuple2<Long, Long>(tp._1.original.blockId, tp._2.original.blockId)));
			entry.clonedParts.add(nset.stream().map(tp2 -> new Tuple3<>(tp2._1, tp2._2, 1.0d))
					.collect(Collectors.toCollection(HashSet::new)));
		});

		HashMap<Long, Integer> coverage = new HashMap<>();
		for (HashSet<Tuple2<HashedLinkedBlock, HashedLinkedBlock>> hashSet : this.subgraphs_old) {
			for (Tuple2<HashedLinkedBlock, HashedLinkedBlock> tuple2 : hashSet) {
				coverage.put(tuple2._1.original.blockId, tuple2._1.original.getAsmLines().size());
			}
		}
		entry.similarity = coverage.values().stream().mapToInt(ind -> ind).sum() * 1.0 / funcLength;

		return entry;
	}

	private static boolean compare(Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> t1,
			Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> t2) {
		if (t1._1().links.contains(t2._1().original.blockId) && t1._2().links.contains(t2._2().original.blockId))
			return true;
		if (t2._1().links.contains(t1._1().original.blockId) && t2._2().links.contains(t1._2().original.blockId))
			return true;
		return false;
	}

	private static boolean compare(Tuple2<HashedLinkedBlock, HashedLinkedBlock> t1,
			Tuple2<HashedLinkedBlock, HashedLinkedBlock> t2) {
		if (t1._1.links.contains(t2._1.original.blockId) && t1._2.links.contains(t2._2.original.blockId))
			return true;
		if (t2._1.links.contains(t1._1.original.blockId) && t2._2.links.contains(t1._2.original.blockId))
			return true;
		return false;
	}

}
