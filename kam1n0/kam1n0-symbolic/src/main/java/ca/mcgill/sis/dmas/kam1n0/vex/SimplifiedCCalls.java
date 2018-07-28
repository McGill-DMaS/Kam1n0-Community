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
package ca.mcgill.sis.dmas.kam1n0.vex;

import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

public class SimplifiedCCalls {

	private static Logger logger = LoggerFactory.getLogger(SimplifiedCCalls.class);

	public static interface SimplifiedCallFunction {
		public ComputationNode calculate(ComputationGraph graph, VexVariableType type, List<ComputationNode> args);
	}

	private static HashMap<String, SimplifiedCallFunction> callees = new HashMap<>();
	static {
		callees.put("x86g_use_seg_selector", SimplifiedCCalls::_x86g_use_seg_selector);
	}

	public static boolean implemented(String name) {
		return callees.containsKey(name);
	}

	public static ComputationNode call(String name, ComputationGraph graph, VexVariableType type,
			List<ComputationNode> args) {
		if (name != null && implemented(name)) {
			SimplifiedCallFunction callee = callees.get(name);
			return callee.calculate(graph, type, args);
		} else
			return null;
	}

	public static ComputationNode _x86g_use_seg_selector(ComputationGraph graph, VexVariableType type,
			List<ComputationNode> args) {

		if (args.size() != 4) {
			logger.error("_x86g_use_seg_selector nees 4 argument but {} provided.", args.size());
			return null;
		}

		// simplified as:
		// [gdt + gs]+ addr
		// In fact: [gdt.base + gs*8].base + addr
		ComputationNode ldt = args.get(0);
		ComputationNode gdt = args.get(1);
		ComputationNode gs = args.get(2); // selector
		ComputationNode addr = args.get(3);

		ComputationNode mem = graph.memory.readMem(-1, gdt.cal(VexOperationType.Iop_Add64, graph, gs), type,
				graph.arch.info.endness, graph);
		return mem.cal(VexOperationType.Iop_Add64, graph, addr);

	}
}
