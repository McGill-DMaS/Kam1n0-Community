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

import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.StmLoadGType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

import javax.swing.text.ComponentView;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph.NodeType;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;

public class StmLoadG extends VexStatement {

	public VexEndnessType end;
	public StmLoadGType cvt;
	public int dst_unsigned;
	public VexExpression addr;
	public VexExpression alt;
	public VexExpression guard;

	@JsonIgnore
	private boolean updatedTmp = false;

	public StmLoadG(@JsonProperty("end") VexEndnessType end, @JsonProperty("cvt") StmLoadGType cvt,
			@JsonProperty("dst_unsigned") int dst_unsigned, @JsonProperty("addr") VexExpression addr,
			@JsonProperty("alt") VexExpression alt, @JsonProperty("guard") VexExpression guard) {
		super();
		this.end = end;
		this.cvt = cvt;
		this.dst_unsigned = dst_unsigned;
		this.addr = addr;
		this.alt = alt;
		this.guard = guard;
		this.tag = VexStatementType.Ist_LoadG;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {

		ComputationNode addr = this.addr.getNode(graph, this.ina);
		ComputationNode memVar = graph.memory.readMem(this.ina, addr, cvt.toTypeInformation().argType.get(0), end,
				graph);

		VexOperationType op = cvt.getTypeConversionOpr();
		if (op != null) {
			ComputationNode conversionNode = new ComputationNode(op);
			memVar = graph.addComputationNode(conversionNode, memVar);
		}

		ComputationNode tmpVar = graph.getTmpVar(dst_unsigned);
		if (this.guard != null) {
			ComputationNode alt = this.alt.getNode(graph, this.ina);
			ComputationNode guard = this.guard.getNode(graph, this.ina);
			ComputationNode ifc = graph.createCondition(guard, memVar, alt);
			graph.assignValue(ifc, tmpVar);
		} else {
			graph.assignValue(memVar, tmpVar);
		}

		ComputationNode node = tmpVar;
		return node;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		if (addr != null)
			addr.updateTmpOffset(newOffset);
		if (alt != null)
			alt.updateTmpOffset(newOffset);
		if (guard != null)
			guard.updateTmpOffset(newOffset);

		if (!updatedTmp) {
			dst_unsigned += newOffset;
			updatedTmp = true;
		}

	}

	@Override
	public String toStr(VexToStrState state) {
		String dataStr = "if(" + guard.toStr(state) + "==1)then{[" + addr.toStr(state) + "]}else{" + alt.toStr(state)
				+ "}";
		if (!state.simplifyTmpVariables)
			return "t" + dst_unsigned + "=" + dataStr;
		state.tmpMemory.put(dst_unsigned, dataStr);
		return StringResources.STR_EMPTY;
	}
}
