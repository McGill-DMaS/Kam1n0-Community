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
package ca.mcgill.sis.dmas.kam1n0.app.clone.adata;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneGraph.FunctionNode;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneGraph.Link;

public class FunctionCloneDataUnit {

	public FunctionCloneDataUnit(ArrayList<FunctionCloneDetectionResultForWeb> results) {
		this.results = results;
	}

	public FunctionCloneDataUnit() {
	}

	public ArrayList<FunctionCloneDetectionResultForWeb> results;

	public FunctionCloneGraph cloneGraph;

	public long takenTime = 0;

	public void generateCloneGraph() {
		cloneGraph = new FunctionCloneGraph();

		// translate binary id
		HashSet<String> binaryIDs = new HashSet<>();
		for (FunctionCloneDetectionResultForWeb result : results) {
			binaryIDs.add(result.function.binaryId);
			for (FunctionCloneEntryForWeb clone : result.clones) {
				binaryIDs.add(clone.binaryId);
			}
		}

		// translate binary id
		HashMap<String, Integer> binaryIDMap = new HashMap<>();
		int bid = 0;
		for (String bidStr : binaryIDs) {
			binaryIDMap.put(bidStr, bid);
			bid++;
		}

		// translate function id for force graph
		// add nodes for force graph
		// this block is for target function
		// fids align as: t1, t2, t3 ..... s1, s2, s3,.... (two part)
		int fid = 0;
		HashMap<String, Integer> functionIDTranslateMap = new HashMap<>();
		for (FunctionCloneDetectionResultForWeb result : results) {
			if (functionIDTranslateMap.containsKey(result.function.functionId))
				continue;
			// target functions:
			FunctionNode node = new FunctionNode();
			node.binaryGroupID = binaryIDMap.get(result.function.binaryId);
			node.binaryGroupName = result.function.binaryName;
			node.name = result.function.functionName;
			cloneGraph.nodes.add(node);
			functionIDTranslateMap.put(result.function.functionId, fid);
			fid++;
		}

		for (FunctionCloneDetectionResultForWeb result : results) {
			// source functions:
			for (FunctionCloneEntryForWeb clone : result.clones) {
				FunctionNode src_node = new FunctionNode();
				src_node.binaryGroupID = binaryIDMap.get(clone.binaryId);
				src_node.binaryGroupName = clone.binaryName;
				src_node.name = clone.functionName;
				if (!functionIDTranslateMap.containsKey(clone.functionId)) {
					cloneGraph.nodes.add(src_node);
					functionIDTranslateMap.put(clone.functionId, fid);
					fid++;
				}
			}
		}

		// add links:
		for (FunctionCloneDetectionResultForWeb result : results) {

			for (FunctionCloneEntryForWeb clone : result.clones) {
				Link link = new Link();
				link.source = functionIDTranslateMap.get(result.function.functionId);
				link.target = functionIDTranslateMap.get(clone.functionId);
				link.value = clone.similarity;
				;

				FunctionNode node = cloneGraph.nodes.get(link.source);
				node.clones.add(new Double[] { (double) link.target, link.value });

				node = cloneGraph.nodes.get(link.target);
				node.clones.add(new Double[] { (double) link.source, link.value });

				cloneGraph.links.add(link);
			}

		}

	}

	public static FunctionCloneDataUnit Merge(List<FunctionCloneDataUnit> units) {
		FunctionCloneDataUnit data = new FunctionCloneDataUnit();
		data.results = new ArrayList<>();
		units.stream().forEach(unit -> data.results.addAll(unit.results));
		return data;
	}
}
