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
package ca.mcgill.sis.dmas.kam1n0.vex.statements;

import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;

public class StmStore extends VexStatement {
	public VexEndnessType end;
	public VexExpression addr;
	public VexExpression data;

	public StmStore(@JsonProperty("end") VexEndnessType end, @JsonProperty("addr") VexExpression addr,
			@JsonProperty("data") VexExpression data) {
		super();
		this.end = end;
		this.addr = addr;
		this.data = data;
		this.tag = VexStatementType.Ist_Store;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		ComputationNode addr = this.addr.getNode(graph, this.ina);
		ComputationNode data = this.data.getNode(graph, this.ina);
		ComputationNode node = graph.memory.writeMem(addr, data, end, graph);
		// Node memVar = graph.create(addr, data.size, end);
		// node = new Node(tag);
		// graph.addComputationNode(node, data, memVar);
		return node;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		addr.updateTmpOffset(newOffset);
		data.updateTmpOffset(newOffset);

	}

	@Override
	public String toStr(VexToStrState state) {
		return "[" + addr.toStr(state) + "]=" + data.toStr(state);
	}
}
