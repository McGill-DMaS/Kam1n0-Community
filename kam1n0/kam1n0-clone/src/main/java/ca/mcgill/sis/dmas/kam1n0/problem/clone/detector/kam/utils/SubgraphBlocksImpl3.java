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
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stringtemplate.v4.compiler.STParser.notConditional_return;

import com.google.common.collect.HashMultimap;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocks.HashedLinkedBlock;
import scala.Tuple3;

public class SubgraphBlocksImpl3 implements Serializable {

	private static Logger logger = LoggerFactory.getLogger(SubgraphBlocksImpl3.class);

	private static final long serialVersionUID = -2343845285400479014L;

	public static class Link {
		public HashedLinkedBlock src;
		public HashedLinkedBlock tar;
		public double score;

		public Link(Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double> tp) {
			this.src = tp._2();
			this.tar = tp._1();
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

	public static class Link2 {
		public Block src;
		public Block tar;
		public double score;

		public Link2(Tuple3<Block, Block, Double> tp) {
			this.src = tp._2();
			this.tar = tp._1();
			this.score = tp._3();
		}

		public String identifier() {
			return this.src.blockId + "-" + this.tar.blockId;
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
			return "(" + this.src.blockName + "," + this.tar.blockName + "," + score + ")";
		}
	}

	public static class Subgraph extends HashSet<Link> {

		private static final long serialVersionUID = 2243945120253674275L;
		private double score;

		public Subgraph() {
		}

		public Subgraph(List<Link> glks) {
			super(glks);
		}

		public void cal() {
			this.score = this.stream().mapToDouble(lk -> lk.score * lk.src.original.codesSize).sum();
		}

		public void removeSrcAny(Set<Long> srcs) {
			this.removeAll(
					this.stream().filter(lk -> srcs.contains(lk.src.original.blockId)).collect(Collectors.toSet()));
		}

		public void removeTarAny(Set<Long> tars) {
			this.removeAll(
					this.stream().filter(lk -> tars.contains(lk.tar.original.blockId)).collect(Collectors.toSet()));
		}

		public Set<Long> tars() {
			return this.stream().map(lk -> lk.tar.original.blockId).collect(Collectors.toSet());
		}

		public Set<Long> srcs() {
			return this.stream().map(lk -> lk.src.original.blockId).collect(Collectors.toSet());
		}

		public String toString() {
			return this.tars() + " / " + this.srcs();
		}
	}

	public static class Subgraph2 extends HashSet<Link2> {

		private static final long serialVersionUID = 2243945120253674275L;
		private double score;

		public Subgraph2() {
		}

		public Subgraph2(List<Link2> glks) {
			super(glks);
		}

		public void cal() {
			this.score = this.stream().mapToDouble(lk -> lk.score * lk.tar.codesSize).sum();
		}

		public void removeSrcAny(Set<Long> srcs) {
			this.removeAll(this.stream().filter(lk -> srcs.contains(lk.src.blockId)).collect(Collectors.toSet()));
		}

		public void removeTarAny(Set<Long> tars) {
			this.removeAll(this.stream().filter(lk -> tars.contains(lk.tar.blockId)).collect(Collectors.toSet()));
		}

		public Set<Long> tars() {
			return this.stream().map(lk -> lk.tar.blockId).collect(Collectors.toSet());
		}

		public Set<Long> srcs() {
			return this.stream().map(lk -> lk.src.blockId).collect(Collectors.toSet());
		}

		public String toString() {
			return this.tars() + " / " + this.srcs();
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

	public static SubgraphBlocksImpl3 mergeSingles(
			Iterable<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> pairs3) {

		HashMap<String, Link> links = new HashMap<>();
		StreamSupport.stream(pairs3.spliterator(), false).map(tp -> new Link(tp))
				.forEach(lk -> links.compute(lk.identifier(), (k, v) -> (v == null || lk.score > v.score) ? lk : v));
		HashSet<Link> uniques = new HashSet<>(links.values());
		SubgraphBlocksImpl3 result = new SubgraphBlocksImpl3();

		while (uniques.size() != 0) {
			Link taken = uniques.stream().findAny().get();
			uniques.remove(taken);
			List<Link> glks = new ArrayList<>();
			glks.add(taken);
			int ind = 0;
			while (ind < glks.size()) {
				Link tar = glks.get(ind);
				Set<Link> extds = uniques.parallelStream().filter(src -> compare(tar, src)).collect(Collectors.toSet());
				glks.addAll(extds);
				uniques.removeAll(extds);
				ind++;
			}
			Subgraph subgraph = new Subgraph(glks);
			subgraph.cal();
			result.subgraphs.add(subgraph);
		}
		return result;
	}

	public static FunctionCloneEntry mergeSingles2(int funcLength, Iterable<Tuple3<Block, Block, Double>> pairs3) {

		ArrayList<Subgraph2> subgraphs = new ArrayList<>();

		// String fname = StreamSupport.stream(pairs3.spliterator(),
		// false).findAny().get()._2().functionName;

		// System.out.println("preparing map for " + fname);
		HashMap<String, Link2> links = new HashMap<>();
		StreamSupport.stream(pairs3.spliterator(), false).map(tp -> new Link2(tp))
				.forEach(lk -> links.compute(lk.identifier(), (k, v) -> (v == null || lk.score > v.score) ? lk : v));
		HashMultimap<Long, Long> callers = HashMultimap.create();
		HashMultimap<Long, Long> callees = HashMultimap.create();
		// System.out.println("preparing links for " + fname);
		for (Link2 link : links.values()) {
			for (Long callee : link.src.callingBlocks) {
				if (link.src.blockId != callee.longValue()) {
					callees.put(link.src.blockId, callee);
					callers.put(callee, link.src.blockId);
				}
			}
			for (Long callee : link.tar.callingBlocks) {
				if (link.tar.blockId != callee.longValue()) {
					callees.put(link.tar.blockId, callee);
					callers.put(callee, link.tar.blockId);
				}
			}
		}

		while (links.size() != 0) {
			Link2 taken = links.values().stream().findAny().get();
			links.remove(taken.identifier());
			List<Link2> glks = new ArrayList<>();
			glks.add(taken);
			int ind = 0;
			while (ind < glks.size()) {
				Link2 lnk = glks.get(ind);
				// anything calling to tar and src
				{
					Set<Long> tars = callers.get(lnk.tar.blockId);
					Set<Long> srcs = callers.get(lnk.src.blockId);
					for (Long s : srcs)
						for (Long t : tars) {
							Link2 candidate = links.get(s + "-" + t);
							if (candidate != null) {
								glks.add(candidate);
								links.remove(candidate.identifier());
							}
						}
				}
				// anything calling from tar and src
				{
					Set<Long> tars = callees.get(lnk.tar.blockId);
					Set<Long> srcs = callees.get(lnk.src.blockId);
					for (Long s : srcs)
						for (Long t : tars) {
							Link2 candidate = links.get(s + "-" + t);
							if (candidate != null) {
								glks.add(candidate);
								links.remove(candidate.identifier());
							}
						}
				}
				ind++;
				// System.out.println(StringResources.format("{}/{}-{}", ind, links.size(),
				// fname));
			}
			Subgraph2 subgraph = new Subgraph2(glks);
			subgraph.cal();
			subgraphs.add(subgraph);

		}

		Block block = subgraphs.get(0).stream().findAny().get().src;
		FunctionCloneEntry entry = new FunctionCloneEntry(block, 0);

		subgraphs.sort((g1, g2) -> Double.compare(g1.score, g2.score));
		ArrayList<Subgraph2> picks = new ArrayList<>();

		for (int i = subgraphs.size() - 1; i >= 0; i--) {
			Subgraph2 largest = subgraphs.get(i);
			subgraphs.remove(i);
			if (largest.size() < 1)
				continue;
			picks.add(largest);
			Set<Long> tars = largest.tars();
			Set<Long> srcs = largest.srcs();
			subgraphs.stream().forEach(gp -> {
				gp.removeSrcAny(srcs);
				gp.removeTarAny(tars);
				gp.cal();
			});
			subgraphs.sort((g1, g2) -> Double.compare(g1.score, g2.score));
		}

		picks.forEach(graph -> entry.clonedParts
				.add(graph.stream().map(lk -> new Tuple3<>(lk.tar.blockId, lk.src.blockId, lk.score))
						.collect(Collectors.toCollection(HashSet::new))));

		// List<Subgraph> gs = picks.stream().filter(graph -> graph.size() >
		// 2).collect(Collectors.toList());
		// if (gs.size() > 0)
		// gs.stream().forEach(System.out::println);
		// if(picks.size()==1) {
		// picks.get(0).forEach(lk->{
		// System.out.println(lk.tar.blockName + "," + lk.tar.codesSize + "," +
		// lk.src.blockName + "," + lk.src.codesSize);
		// });
		// System.out.println();
		// }
		HashMap<Long, Double> hashMap = new HashMap<>();
		picks.stream().flatMap(g -> g.stream()).forEach(lk -> hashMap.compute(lk.tar.blockId,
				(k, v) -> v == null ? lk.score * lk.tar.codesSize : Math.max(lk.score * lk.tar.codesSize, v)));
		// entry.similarity = picks.stream().mapToDouble(g -> g.score).sum() * 1.0 /
		// (Math.abs(funcLength));
		double sum = hashMap.values().stream().mapToDouble(v -> v).sum() * 2;
		entry.similarity = sum / (Math.abs(funcLength) + Math.abs(entry.codeSize));
		return entry;
	}

	public FunctionCloneEntry toFunctionCloneEntry(int funcLength) {
		FunctionCloneEntry entry = new FunctionCloneEntry();
		Block block = this.subgraphs.get(0).stream().findAny().get().tar.original;
		entry.functionId = block.functionId;
		entry.functionName = block.functionName;
		entry.binaryId = block.binaryId;
		entry.binaryName = block.binaryName;

		this.subgraphs.sort((g1, g2) -> Double.compare(g1.score, g2.score));
		ArrayList<Subgraph> picks = new ArrayList<>();

		for (int i = this.subgraphs.size() - 1; i >= 0; i--) {
			Subgraph largest = this.subgraphs.get(i);
			this.subgraphs.remove(i);
			if (largest.size() < 1)
				continue;
			picks.add(largest);
			Set<Long> tars = largest.tars();
			Set<Long> srcs = largest.srcs();
			this.subgraphs.stream().forEach(gp -> {
				gp.removeSrcAny(srcs);
				gp.removeTarAny(tars);
				gp.cal();
			});
			this.subgraphs.sort((g1, g2) -> Double.compare(g1.score, g2.score));
		}

		picks.forEach(graph -> entry.clonedParts
				.add(graph.stream().map(lk -> new Tuple3<>(lk.src.original.blockId, lk.tar.original.blockId, lk.score))
						.collect(Collectors.toCollection(HashSet::new))));

		// List<Subgraph> gs = picks.stream().filter(graph -> graph.size() >
		// 2).collect(Collectors.toList());
		// if (gs.size() > 0)
		// gs.stream().forEach(System.out::println);

		entry.similarity = picks.stream().mapToDouble(g -> g.score).sum() * 1.0 / (Math.abs(funcLength));
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
