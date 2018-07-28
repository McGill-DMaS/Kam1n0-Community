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

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.Endianness;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;
import ca.mcgill.sis.dmas.kam1n0.vex.variable.IRRegArray;

public class StmPutI extends VexStatement {
	public IRRegArray descr; /* Part of guest state treated as circular */
	public VexExpression ix; /* Variable part of index into array */
	public int bias; /* Constant offset part of index into array */
	public VexExpression data; /* The value to write */

	public StmPutI(@JsonProperty("descr") IRRegArray descr, @JsonProperty("ix") VexExpression ix,
			@JsonProperty("bias") int bias, @JsonProperty("data") VexExpression data) {
		super();
		this.descr = descr;
		this.ix = ix;
		this.bias = bias;
		this.data = data;
		this.tag = VexStatementType.Ist_PutI;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		ix.updateTmpOffset(newOffset);
		data.updateTmpOffset(newOffset);
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		ComputationNode ixNode = ix.getNode(graph, ina);
		int array_size = descr.type.numOfBit();
		int array_base = descr.base;

		ComputationNode array_index = ixNode.calWithVal(VexOperationType.Iop_Add64, graph, bias);
		array_index = array_index.calWithVal(VexOperationType.Iop_DivModS64to64, graph, descr.numElements);
		ComputationNode offset = array_index.calWithVal(VexOperationType.Iop_Mul64, graph, array_size)
				.calWithVal(VexOperationType.Iop_Add64, graph, array_base);

		return graph.memory.writeMem(offset, data.getNode(graph, ina), graph.arch.info.endness, graph);
	}

	@Override
	public String toStr(VexToStrState state) {
		return "Reg(" + ix.toStr(state) + "+" + bias + ")%" + descr.numElements + "*" + descr.type.numOfBit() + "+"
				+ descr.base + ")=" + data.toStr(state);
	}

}
