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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Stack;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;

public class GraphletGenerator extends SignatureGenerator {

	private static Logger logger = LoggerFactory
			.getLogger(GraphletGenerator.class);

	public GraphletGenerator(int K, boolean extended) {
		this.K = K;
		this.extended = extended;
	}

	int K = 3;
	boolean extended = false;
	boolean debug = true;

	/**
	 * depth-first traversal for generating graphlets. However, it is based on
	 * sliding window. All generators are not thread-safe. (cant be shared).
	 * 
	 * @param function
	 * @param K
	 * @param extended
	 * @return
	 */
	public ArrayList<Graphlet> generateGraphlets(
			Function function, int K, boolean extended) {

		HashMap<Long, Block> map = new HashMap<>();
		for (Block block : function) {
			map.put(block.blockId, block);
		}
		Stack<Block> window = new Stack<>();
		ArrayList<Graphlet> reslt = new ArrayList<>();
		for (Block block : function) {
			traverse(window, reslt, block, function.blocks, map, K - 1);
		}

		return reslt;
	}

	@SuppressWarnings("unused")
	/**
	 * m-way combination to generate sub-graph (not-used, costly)
	 * @param window
	 * @param k
	 * @param blocks
	 * @param extended
	 * @return
	 */
	private ArrayList<Graphlet> genResult(HashSet<Block> window,
			int k, ArrayList<Block> blocks, boolean extended) {
		ArrayList<Block> ls = new ArrayList<>(window);
		ArrayList<Graphlet> results = new ArrayList<>();
		if (debug)
			logger.info("windows: {}", window.size());
		combination(ls, K).forEach(s -> {
			Graphlet g = new Graphlet(new ArrayList<>(s), extended, blocks);
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
	 */
	public void traverse(Stack<Block> window,
			ArrayList<Graphlet> graphlets, Block block,
			List<Block> allBlks,
			HashMap<Long, Block> map, int localK) {
		window.push(block);
		if (localK == 0) {
			graphlets.add(new Graphlet(window, extended, allBlks));
			window.pop();
			return;
		} else {
			for (Long callee : block.callingBlocks) {
				Block calleeBlock = map.get(callee);
				if (calleeBlock != null) {
					traverse(window, graphlets, calleeBlock, allBlks, map,
							localK - 1);
				}
			}
			window.pop();
			return;
		}
	}

	@Override
	public ArrayList<String> generateSignatureList(Function func) {
		ArrayList<String> sigs = new ArrayList<>();
		generateGraphlets(func, K, extended)
				.forEach(g -> sigs.add(g.signature));
		return sigs;
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("mode", "graphlet", "K",
				K, "extended", extended);
	}

	public static ArrayList<ArrayList<Block>> combination(
			List<Block> elements, int K) {

		ArrayList<ArrayList<Block>> result = new ArrayList<>();

		// get the length of the array
		// e.g. for {'A','B','C','D'} => N = 4
		int N = elements.size();

		if (K > N) {
			// System.out.println("Invalid input, K > N");
			return result;
		}
		// get the combination by index
		// e.g. 01 --> AB , 23 --> CD
		int combination[] = new int[K];

		// position of current index
		// if (r = 1) r*
		// index ==> 0 | 1 | 2
		// element ==> A | B | C
		int r = 0;
		int index = 0;

		while (r >= 0) {
			// possible indexes for 1st position "r=0" are "0,1,2" --> "A,B,C"
			// possible indexes for 2nd position "r=1" are "1,2,3" --> "B,C,D"

			// for r = 0 ==> index < (4+ (0 - 2)) = 2
			if (index <= (N + (r - K))) {
				combination[r] = index;

				// if we are at the last position print and increase the index
				if (r == K - 1) {

					// do something with the combination e.g. add to list or
					// print
					// print(combination, elements);
					ArrayList<Block> subSet = new ArrayList<>();
					for (int i : combination) {
						subSet.add(elements.get(i));
					}
					result.add(subSet);
					index++;
				} else {
					// select index for next position
					index = combination[r] + 1;
					r++;
				}
			} else {
				r--;
				if (r > 0)
					index = combination[r] + 1;
				else
					index = combination[0] + 1;
			}
		}
		return result;
	}

	public static ArrayList<ArrayList<Integer>> combinationTest(
			List<Integer> elements, int K) {

		ArrayList<ArrayList<Integer>> result = new ArrayList<>();

		// get the length of the array
		// e.g. for {'A','B','C','D'} => N = 4
		int N = elements.size();

		if (K > N) {
			// System.out.println("Invalid input, K > N");
			return result;
		}
		// get the combination by index
		// e.g. 01 --> AB , 23 --> CD
		int combination[] = new int[K];

		// position of current index
		// if (r = 1) r*
		// index ==> 0 | 1 | 2
		// element ==> A | B | C
		int r = 0;
		int index = 0;

		while (r >= 0) {
			// possible indexes for 1st position "r=0" are "0,1,2" --> "A,B,C"
			// possible indexes for 2nd position "r=1" are "1,2,3" --> "B,C,D"

			// for r = 0 ==> index < (4+ (0 - 2)) = 2
			if (index <= (N + (r - K))) {
				combination[r] = index;

				// if we are at the last position print and increase the index
				if (r == K - 1) {

					// do something with the combination e.g. add to list or
					// print
					// print(combination, elements);
					ArrayList<Integer> subSet = new ArrayList<>();
					for (int i : combination) {
						subSet.add(elements.get(i));
					}
					result.add(subSet);
					index++;
				} else {
					// select index for next position
					index = combination[r] + 1;
					r++;
				}
			} else {
				r--;
				if (r > 0)
					index = combination[r] + 1;
				else
					index = combination[0] + 1;
			}
		}
		return result;
	}

	public static void main(String[] args) {
		ArrayList<Integer> elements = Lists.newArrayList(1, 2, 3, 4, 5, 6, 7,
				8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20);
		combinationTest(elements, 5).forEach(t -> System.out.println(t));

	}
}
