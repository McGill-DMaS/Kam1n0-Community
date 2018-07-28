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
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.stylesheets.LinkStyle;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocks.HashedLinkedBlock;
import scala.Tuple2;
import scala.Tuple3;

public class SubgraphBlocksImpl2 implements Serializable {

	private static Logger logger = LoggerFactory.getLogger(SubgraphBlocksImpl2.class);

	private static final long serialVersionUID = -2343845285400479014L;

	public static class Link {
		public HashedLinkedBlock src;
		public HashedLinkedBlock tar;
		public double score;

		public Link(Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> tp) {
			this.src = tp._1();
			this.tar = tp._2();
			this.score = tp._3();
		}

		public String identifier() {
			return this.src.original.blockId + "-" + this.tar.original.blockId;
		}

		@Override
		public int hashCode() {
			return this.identifier().hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof Link) {
				Link lk = (Link) obj;
				return this.identifier().equals(lk.identifier());
			}
			return false;
		}

		@Override
		public String toString() {
			return "(" + this.src.original.blockName + "," + this.tar.original.blockName + "," + score + ")";
		}
	}

	public static class Subgraph extends ArrayList<Link> {

		private static final long serialVersionUID = 2243945120253674275L;

		public Set<Long> tarCoverage() {
			return this.stream().map(lk -> lk.tar.original.blockId).collect(Collectors.toSet());
		}

		public Set<Long> srcCoverage() {
			return this.stream().map(lk -> lk.src.original.blockId).collect(Collectors.toSet());
		}

		@Override
		public String toString() {
			return tarCoverage().size() + "-" + srcCoverage().size() + "/" + this.size() + ":"
					+ StringResources.FORMAT_AR4D.format(this.score);
		}

		public double score;

		public void cal() {
			this.score = this.stream().mapToDouble(lk -> lk.score * lk.src.original.getAsmLines().size()).sum();
		}

		public boolean containsSrcAny(HashSet<Long> covered_src) {
			return this.stream().filter(lk -> covered_src.contains(lk.src.original.blockId)).findAny().isPresent();
		}

		public boolean containsTarAny(HashSet<Long> covered_tar) {
			return this.stream().filter(lk -> covered_tar.contains(lk.tar.original.blockId)).findAny().isPresent();
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

	// (tar, src, score)
	public ArrayList<Subgraph> subgraphs = new ArrayList<>();

	public static SubgraphBlocksImpl2 mergeSingles(
			Iterable<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> pairs3) {

		HashMap<String, Link> links = new HashMap<>();
		StreamSupport.stream(pairs3.spliterator(), false).map(tp -> new Link(tp))
				.forEach(lk -> links.compute(lk.identifier(), (k, v) -> (v == null || lk.score > v.score) ? lk : v));
		HashSet<Link> uniques = new HashSet<>(links.values());
		SubgraphBlocksImpl2 result = new SubgraphBlocksImpl2();

		while (uniques.size() != 0) {
			Link taken = uniques.stream().findAny().get();
			uniques.remove(taken);
			Subgraph subgraph = new Subgraph();
			subgraph.add(taken);
			int ind = 0;
			while (ind < subgraph.size()) {
				Link tar = subgraph.get(ind);
				Set<Link> extds = uniques.parallelStream().filter(src -> compare(tar, src)).collect(Collectors.toSet());
				subgraph.addAll(extds);
				uniques.removeAll(extds);
				ind++;
			}
			subgraph.cal();
			result.subgraphs.add(subgraph);
		}
		result.subgraphs.sort((g1, g2) -> Double.compare(g2.score, g1.score));

		return result;
	}

	public FunctionCloneEntry toFunctionCloneEntry(int funcLength) {
		FunctionCloneEntry entry = new FunctionCloneEntry();
		Block block = this.subgraphs.get(0).stream().findAny().get().tar.original;
		entry.functionId = block.functionId;
		entry.functionName = block.functionName;
		entry.binaryId = block.binaryId;
		entry.binaryName = block.binaryName;

		HashSet<Long> covered_tar = new HashSet<>();
		HashSet<Long> covered_src = new HashSet<>();
		ArrayList<Subgraph> picks = new ArrayList<>();

		this.subgraphs.forEach(graph -> {
			if (!graph.containsTarAny(covered_tar) && !graph.containsSrcAny(covered_src)) {
				picks.add(graph);
				covered_tar.addAll(graph.tarCoverage());
				covered_src.addAll(graph.srcCoverage());
			}
		});

		picks.forEach(graph -> entry.clonedParts
				.add(graph.stream().map(lk -> new Tuple3<>(lk.src.original.blockId, lk.tar.original.blockId, lk.score))
						.collect(Collectors.toCollection(HashSet::new))));

		entry.similarity = picks.stream().mapToDouble(g -> g.score).sum() * 1.0 / funcLength;
		return entry;
	}

	private static boolean compare(Link t1, Link t2) {
		if (t1.src.links.contains(t2.src.original.blockId) && t1.tar.links.contains(t2.tar.original.blockId)) // above
			return true;
		if (t2.src.links.contains(t1.src.original.blockId) && t2.tar.links.contains(t1.tar.original.blockId)) // below
			return true;
		return false;
	}

}
