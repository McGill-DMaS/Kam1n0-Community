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
package ca.mcgill.sis.dmas.kam1n0.vex.expression;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;

public class ExRdTmp extends VexExpression {

	public int tmp_unsigned;

	@JsonIgnore
	private boolean tmpUpdated = false;

	public ExRdTmp(@JsonProperty("tmp_unsigned") int valunsigned) {
		this.tmp_unsigned = valunsigned;
		this.tag = VexExpressionType.Iex_RdTmp;
	}

	@Override
	public ComputationNode getNode(ComputationGraph graph, long ina) {
		ComputationNode node = graph.getTmpVar(tmp_unsigned);
		return node;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		if (!tmpUpdated) {
			tmp_unsigned += newOffset;
			tmpUpdated = true;
			// if (tmp_unsigned > 1000)
			// System.out.println("ERROR");
		}
	}

	@Override
	public String toStr(VexToStrState state) {
		if (!state.simplifyTmpVariables)
			return "t" + tmp_unsigned;
		String dataStr = state.tmpMemory.get(tmp_unsigned);
		if (dataStr != null)
			return dataStr;
		else
			return "t" + tmp_unsigned;
	}

}
