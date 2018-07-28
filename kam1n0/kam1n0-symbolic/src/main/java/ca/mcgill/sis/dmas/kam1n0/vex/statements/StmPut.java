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

import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmPut extends VexStatement {

	public int offset;
	public VexExpression data;

	public StmPut(@JsonProperty("offset") int offset, @JsonProperty("data") VexExpression data) {
		super();
		this.offset = offset;
		this.data = data;
		this.tag = VexStatementType.Ist_Put;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		ComputationNode data = this.data.getNode(graph, this.ina);
		ComputationNode reg = graph.getReg(offset, data.valType.outputType);
		graph.assignValue(data, reg);
		ComputationNode node = reg;
		return node;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		data.updateTmpOffset(newOffset);
	}

	@Override
	public String toStr(VexToStrState state) {
		if (state.ignorePC && state.arch.type.getGuestInfo().isProgramCounter(this.offset))
			return StringResources.STR_EMPTY;
		if (state.regularRegOnly && !state.arch.type.getGuestInfo().isGeneralReg(this.offset))
			return StringResources.STR_EMPTY;
		return state.arch.type.getGuestInfo().registerName.get(offset) + "=" + data.toStr(state);
	}

}
