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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.utils;

import gnu.trove.map.hash.TLongObjectHashMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;

public class ColoredGraphletGenerator extends SignatureGenerator {

	public ColoredGraphletGenerator(int K) {
		this.K = K;
	}

	int K = 3;

	/**
	 * depth-first traversal for generating graphlets. However, it is based on
	 * sliding window. All generators are not thread-safe. (cant be shared).
	 * 
	 * @param function
	 * @param K
	 * @param extended
	 * @return
	 */
	public ArrayList<ColoredGraphlet> generateGraphletColors(Function function,
			int K, TLongObjectHashMap<String> tags) {
		HashMap<Long, Block> map = new HashMap<>();
		for (Block block : function) {
			map.put(block.blockId, block);
		}
		Stack<Block> window = new Stack<>();
		ArrayList<ColoredGraphlet> graplets = new ArrayList<>();
		for (Block block : function) {
			traverse(window, block, graplets, map, K - 1, tags);
		}

		return graplets;
	}

	public ArrayList<ColoredGraphlet> generateGraphletColors(Function function,
			int K) {
		return generateGraphletColors(function, K, assignColor(function));
	}

	@SuppressWarnings("unchecked")
	/**
	 * order matters.
	 */
	public ImmutableList<EntryPair<ImmutableSet<String>, String>> colorTbl = ImmutableList
			.of(new EntryPair<ImmutableSet<String>, String>(ImmutableSet.of(
					"movs", "cmps", "sca", "lod", "stos", "rep"), "String"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("mov", "cmov", "cwd", "cdq"), "DataTransfer"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("push", "pop"), "Stack"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("sub", "add", "shr", "shl", "sbb", "sar",
									"adc", "xchg", "imul", "idiv", "mul",
									"div", "inc", "dec", "xadd", "ror", "rol",
									"p"), "Arithmetic"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("call"), "Call"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("lea"), "LEA"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("in", "out"), "IO"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("cmp", "test", "comiss", "ucomi"), "Test"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("j"), "Jump"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("nop", "hlt", "mfence", "sldt", "ret"), "SKIP"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("and", "xor", "not", "or", "bt", "bsr", "neg"),
							"Logic"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("set", "sahf", "cld"), "Flags"),
					new EntryPair<ImmutableSet<String>, String>(ImmutableSet
							.of("fld", "cvt", "vcvt", "maxss", "pun", "shufps",
									"sqrt", "unpck", "f"), "Float"));

	public TLongObjectHashMap<String> assignColor(Function func) {
		TLongObjectHashMap<String> color = new TLongObjectHashMap<>();
		for (Block blk : func) {
			List<List<String>> lines = blk.getAsmLines();
			int sig = 0;
			for (List<String> line : lines) {
				if (line.size() > 1) {
					boolean asignedThisLine = false;
					for (int i = 0; i < colorTbl.size(); ++i) {
						for (String prefix : colorTbl.get(i).key) {
							if (line.get(1).toLowerCase().startsWith(prefix)) {
								sig = sig | (1 << i);
								asignedThisLine = true;
								break;
							}
						}
						if (asignedThisLine)
							break;
					}
				}
			}
			color.put(blk.blockId, Integer.toBinaryString(sig));
		}
		return color;
	}

	/**
	 * use m-way combination to generate sub tree
	 * 
	 * @param window
	 * @param k
	 * @param tags
	 * @return
	 */
	@SuppressWarnings("unused")
	private ArrayList<ColoredGraphlet> genResult(HashSet<Block> window, int k,
			TLongObjectHashMap<String> tags) {
		HashSet<ColoredGraphlet> results = new HashSet<>();
		Set<Set<Block>> subSets = Sets.powerSet(window);
		subSets.stream().filter(s -> s.size() == k).forEachOrdered(s -> {
			ColoredGraphlet g = new ColoredGraphlet(new ArrayList<>(s), tags);
			results.add(g);
		});
		return new ArrayList<>(results);
	}

	/**
	 * depth-first traversing to collect subgraph that has depth at most of k.
	 * 
	 * @param window
	 * @param block
	 * @param map
	 * @param localK
	 * @param extended
	 */
	public void traverse(Stack<Block> window, Block block,
			ArrayList<ColoredGraphlet> rlts, HashMap<Long, Block> map,
			int localK, TLongObjectHashMap<String> tags) {
		window.push(block);
		if (localK == 0) {
			rlts.add(new ColoredGraphlet(window, tags));
			window.pop();
			return;
		} else {
			for (Long callee : block.callingBlocks) {
				Block calleeBlock = map.get(callee);
				if (calleeBlock != null) {
					traverse(window, calleeBlock, rlts, map, localK - 1, tags);
				}
			}
			window.pop();
			return;
		}
	}

	public static void main(String[] args) {
		// BinarySurrogate binary = new BinarySurrogate();
		// binary.name = "test";
		// BlockSurrogate b1 = new BlockSurrogate();
		// b1.sea = 0;
		// b1.src =
		// "4096 push    ebp \r\n4097 mov     ebp, esp \r\n4099 push    ecx \r\n4100 cmp     [ebp+arg_0], 0 \r\n4104 jnz     short loc_100C \r\n";
		// FunctionSurrogate func = new FunctionSurrogate();
		// func.blocks.add(b1);
		// func.name = "testFunc";
		// binary.functions.add(func);
		// binary.processRawBinarySurrogate();
		// ColoredGraphletGenerator gen = new ColoredGraphletGenerator(3);
		// gen.assignColor(binary.toFunction(func)).forEachValue(t -> {
		// System.out.println(t);
		// return true;
		// });
		// // should be 110000110
	}

	@Override
	public ArrayList<String> generateSignatureList(Function func) {
		ArrayList<String> sigs = new ArrayList<>();
		this.generateGraphletColors(func, K)
				.forEach(g -> sigs.add(g.signature));
		return sigs;
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("mode",
				"graphlet-colored", "K", K);
	}
}
