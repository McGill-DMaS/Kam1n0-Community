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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmWrTmp extends VexStatement {

	public int tmp_unsigned;
	public VexExpression data;

	@JsonIgnore
	private boolean tmpUpdated = false;

	public StmWrTmp(@JsonProperty("tmp_unsigned") int tmp_unsigned, @JsonProperty("data") VexExpression data) {
		super();
		this.tmp_unsigned = tmp_unsigned;
		this.data = data;
		this.tag = VexStatementType.Ist_WrTmp;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		ComputationNode node = graph.getTmpVar(tmp_unsigned);
		graph.assignValue(data.getNode(graph, this.ina), node);
		return node;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		data.updateTmpOffset(newOffset);
		if (!tmpUpdated) {
			tmp_unsigned += newOffset;
			tmpUpdated = true;
		}

	}

	@Override
	public String toStr(VexToStrState state) {
		String dataStr = data.toStr(state);
		if (!state.simplifyTmpVariables)
			return "t" + tmp_unsigned + "=" + dataStr;
		state.tmpMemory.put(tmp_unsigned, dataStr);
		return StringResources.STR_EMPTY;
	}
}
