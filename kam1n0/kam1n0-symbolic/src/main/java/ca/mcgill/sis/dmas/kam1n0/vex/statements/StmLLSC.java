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

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmLLSC extends VexStatement {

	public VexEndnessType endness;
	public int result_unsigned;
	public VexExpression addr;
	public VexExpression storedata;

	public StmLLSC(@JsonProperty("endness") VexEndnessType endness,
			@JsonProperty("result_unsigned") int result_unsigned, @JsonProperty("addr") VexExpression addr,
			@JsonProperty("storedata") VexExpression storedata) {
		super();
		this.endness = endness;
		this.result_unsigned = result_unsigned;
		this.addr = addr;
		this.storedata = storedata;
		this.tag = VexStatementType.Ist_LLSC;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		if (addr != null)
			addr.updateTmpOffset(newOffset);
		if (storedata != null)
			storedata.updateTmpOffset(newOffset);

	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		if (storedata == null) {
			ComputationNode tmpVar = graph.getTmpVar(result_unsigned);
			ComputationNode addrNode = addr.getNode(graph, ina);
			// write with address reservation
			ComputationNode data = graph.memory.readMem(ina, addrNode, tmpVar.valType.outputType, endness, graph, true);
			graph.assignValue(data, tmpVar);
			return tmpVar;
		} else {
			ComputationNode tmpVar = graph.getTmpVar(result_unsigned);
			ComputationNode addrNode = addr.getNode(graph, ina);
			ComputationNode data = storedata.getNode(graph, ina);
			ComputationNode writeAttemp = graph.memory.tryWrteMem(addrNode, data, endness, graph);
			graph.assignValue(writeAttemp, tmpVar);
			return tmpVar;
		}

	}

	@Override
	public String toStr(VexToStrState state) {
		if (storedata == null)
			return "t" + result_unsigned + "=Load(" + addr.toStr(state) + ")";
		else
			return "if(" + addr.toStr(state) + " reserved)then{" + "t" + result_unsigned + "=Load(" + addr.toStr(state)
					+ ")}else{Store(" + addr.toStr(state) + "," + storedata.toStr(state) + ");" + " t" + result_unsigned
					+ "=" + storedata.toStr(state) + "}";
	}

}
