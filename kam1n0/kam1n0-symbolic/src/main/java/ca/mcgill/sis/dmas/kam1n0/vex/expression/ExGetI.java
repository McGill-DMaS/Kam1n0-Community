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

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.variable.IRRegArray;

public class ExGetI extends VexExpression {

	public IRRegArray descr;
	public VexExpression expression;

	public int bias;

	public ExGetI(@JsonProperty("descr") IRRegArray descr, @JsonProperty("expression") VexExpression expression,
			int bias) {
		this.tag = VexExpressionType.Iex_GetI;
		this.bias = bias;
		this.expression = expression;
		this.descr = descr;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		expression.updateTmpOffset(newOffset);
	}

	@Override
	public ComputationNode getNode(ComputationGraph graph, long ina) {
		ComputationNode ixNode = expression.getNode(graph, ina);
		int array_size = descr.type.numOfBit();
		int array_base = descr.base;

		ComputationNode array_index = ixNode.calWithVal(VexOperationType.Iop_Add64, graph, bias);
		array_index = array_index.calWithVal(VexOperationType.Iop_DivModS64to64, graph, descr.numElements);
		ComputationNode offset = array_index.calWithVal(VexOperationType.Iop_Mul64, graph, array_size)
				.calWithVal(VexOperationType.Iop_Add64, graph, array_base);

		return graph.memory.readMem(ina, offset, descr.type, graph.arch.info.endness, graph);
	}

	@Override
	public String toStr(VexToStrState state) {
		return "Reg( (" + expression.toStr(state) + "+" + bias + ")%" + descr.numElements + "*" + descr.type.numOfBit()
				+ "+" + descr.base + ")";
	}

}
