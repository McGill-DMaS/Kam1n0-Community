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
package ca.mcgill.sis.dmas.kam1n0.graph;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;

import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

public class StaticMemoryLayout {

	private static Logger logger = LoggerFactory.getLogger(StaticMemoryLayout.class);

	// static version memory layout.
	public HashMap<String, ArrayListMultimap<Integer, ComputationNode>> layout = new HashMap<>();

	public HashSet<String> reserved = new HashSet<>();

	public VexArchitectureType architectureType;

	public StaticMemoryLayout(VexArchitectureType architectureType) {
		this.architectureType = architectureType;
	}

	private int memInd = 0;

	public HashMap<Long, String> dataSection = new HashMap<>();

	public void addData(Long addr, String val) {
		dataSection.put(addr, val);
	}

	public String readData(Long addr, VexVariableType type, VexEndnessType endness) {
		if (dataSection.containsKey(addr)) {
			char[] dat = dataSection.get(addr).toCharArray();
			int num_char = type.numOfBit() / 4;
			StringBuilder sBuilder = new StringBuilder();
			for (int i = 0; i < num_char; ++i) {
				if (i > dat.length - 1)
					break;
				if (endness.equals(VexEndnessType.VexEndnessLE))
					sBuilder.insert(0, dat[i]);
				else
					sBuilder.append(dat[i]);
			}
			// System.out.println(sBuilder.toString());
			if (sBuilder.length() == 0)
				return null;
			else
				return sBuilder.toString();
		}
		return null;
	}

	public ComputationNode readMem(long insAddr, ComputationNode addr, VexVariableType type, VexEndnessType endness,
			ComputationGraph graph) {
		return readMem(insAddr, addr, type, endness, graph, false);
	}

	public ComputationNode readMem(long insAddr, ComputationNode addr, VexVariableType type, VexEndnessType endness,
			ComputationGraph graph, boolean reserved) {

		// check if the value is in code section (pc-relative loads in arm):
		if (insAddr != -1) {
			String val = readData(insAddr, type, endness);
			if (val != null) {
				return graph.getConstant(type.numOfBit(), val);
			}
		}

		// if existed; return latest; (same base same size)
		// if overlapped; create new; (same base different size)
		// if non-existed; create new; (different base)

		String key = addr.traverseId(graph.nodes, 30);

		if (reserved)
			this.reserved.add(key);

		if (layout.containsKey(key)) {
			ArrayListMultimap<Integer, ComputationNode> address = layout.get(key);
			if (address.containsKey(type.numOfBit())) {
				// if existed; return the latest; (same base same size)
				List<ComputationNode> ls = address.get(type.numOfBit());
				return ls.get(ls.size() - 1);
			} else {
				// if overlapped; create new; (same base different size)
				ComputationNode memVarNode = graph.createMemVar(addr, type, endness, memInd, 0);
				memInd++;
				address.put(type.numOfBit(), memVarNode);
				return memVarNode;
			}
		} else {
			// if non-existed; create new; (different base)
			ComputationNode memVarNode = graph.createMemVar(addr, type, endness, memInd, 0);
			memInd++;
			ArrayListMultimap<Integer, ComputationNode> address = ArrayListMultimap.create();
			address.put(type.numOfBit(), memVarNode);
			layout.put(key, address);
			return memVarNode;
		}
	}

	public ComputationNode writeMem(ComputationNode addr, ComputationNode data, VexEndnessType endness,
			ComputationGraph graph) {
		String key = addr.traverseId(graph.nodes, 30);
		return writeMem(addr, key, data, endness, graph);
	}

	public ComputationNode tryWrteMem(ComputationNode addr, ComputationNode data, VexEndnessType endness,
			ComputationGraph graph) {
		String key = addr.traverseId(graph.nodes, 30);
		if (this.reserved.contains(key)) {
			return graph.getConstant(1, 0);
		} else {
			writeMem(addr, key, data, endness, graph);
			return graph.getConstant(1, 1);
		}
	}

	public ComputationNode writeMem(ComputationNode addr, String addrStr, ComputationNode data, VexEndnessType endness,
			ComputationGraph graph) {
		// if existed; create new version;
		// if overlapped; create; create a new version for the overlapped
		// variables;

		String key = addrStr;
		int size = data.valType.outputType.numOfBit();
		if (size == -1)
			logger.error("Computation node does not have size for writing memory. varName: {} sExp: {}", data.varName,
					data.sExpression(graph.nodes));
		if (layout.containsKey(key)) {
			ArrayListMultimap<Integer, ComputationNode> address = layout.get(key);
			// the complete address space for this base is contaminated.
			// create new values for all the contaminated area.
			// it is better to create an operation node named contamination.
			// for now we just create a new node for that

			new HashSet<>(address.keySet()).forEach(sz -> {
				List<ComputationNode> ls = address.get(sz);
				ComputationNode memVarNode = graph.createMemVar(addr, data.valType.outputType, endness, memInd,
						ls.size() - 1);
				memInd++;
				address.put(sz, memVarNode);
			});

			if (address.containsKey(size)) {
				List<ComputationNode> ls = address.get(size);
				ComputationNode dest = ls.get(ls.size() - 1);
				graph.assignValue(data, dest);
				return dest;
			} else {
				ComputationNode dest = graph.createMemVar(addr, data.valType.outputType, endness, memInd, 0);
				memInd++;
				address.put(size, dest);
				graph.assignValue(data, dest);
				return dest;
			}
		} else {
			ComputationNode dest = graph.createMemVar(addr, data.valType.outputType, endness, memInd, 0);
			memInd++;
			ArrayListMultimap<Integer, ComputationNode> address = ArrayListMultimap.create();
			address.put(size, dest);
			layout.put(key, address);
			graph.assignValue(data, dest);
			return dest;
		}

	}

}
