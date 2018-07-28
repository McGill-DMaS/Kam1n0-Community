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
import java.util.List;
import java.util.Stack;

import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.tracelet.DetectorTracelet.PreSplittedBlock;

public class TraceletGenerator {

	/**
	 * depth-first traversal for tracelet
	 * 
	 * @param function
	 * @param K
	 * @return
	 */
	public ArrayList<Tracelet> generateGraphlets(List<PreSplittedBlock> blks,
			int K) {
		ArrayList<Tracelet> results = new ArrayList<>();
		HashMap<Long, PreSplittedBlock> map = new HashMap<>();
		for (PreSplittedBlock block : blks) {
			map.put(block.orinBlock.blockId, block);
		}
		for (PreSplittedBlock block : blks) {
			traverse(new Stack<>(), results, block, map, K - 1);
		}
		return results;
	}

	public void traverse(Stack<PreSplittedBlock> stack,
			ArrayList<Tracelet> results, PreSplittedBlock block,
			HashMap<Long, PreSplittedBlock> map, int localK) {
		stack.push(block);
		if (localK == 0) {
			Tracelet graphlet = new Tracelet(stack);
			results.add(graphlet);
		} else {
			for (Long callee : block.orinBlock.callingBlocks) {
				PreSplittedBlock calleeBlock = map.get(callee);
				if (calleeBlock != null) {
					traverse(stack, results, calleeBlock, map, localK - 1);
				}
			}
		}
		stack.pop();
	}
}
