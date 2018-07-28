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

import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexOperation;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;

public class ExBinop extends VexExpression {

	public VexOperation operation;
	public VexExpression exp1;
	public VexExpression exp2;

	public ExBinop(@JsonProperty("operation") VexOperation operation, @JsonProperty("exp1") VexExpression exp1,
			@JsonProperty("exp2") VexExpression exp2) {
		this.operation = operation;
		this.exp1 = exp1;
		this.exp2 = exp2;
		this.tag = VexExpressionType.Iex_Binop;
	}

	@Override
	public ComputationNode getNode(ComputationGraph graph, long ina) {
		ComputationNode node = new ComputationNode(operation);
		graph.addComputationNode(node, exp1.getNode(graph, ina), exp2.getNode(graph, ina));
		return node;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		exp1.updateTmpOffset(newOffset);
		exp2.updateTmpOffset(newOffset);
	}

	@Override
	public String toStr(VexToStrState state) {
		return operation.toStr() + "(" + exp1.toStr(state) + "," + exp2.toStr(state) + ")";
	}

}
