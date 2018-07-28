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
import ca.mcgill.sis.dmas.kam1n0.vex.VexConstant;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexJumpKind;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmExit extends VexStatement {

	public VexExpression guard;
	public VexConstant dst;
	public VexJumpKind jumpKind;
	public int offsetIP_unsigned;

	public StmExit(@JsonProperty("guard") VexExpression guard, @JsonProperty("dst") VexConstant dst,
			@JsonProperty("jumpKind") VexJumpKind jumpKind, @JsonProperty("offsetIP_unsigned") int offsetIP_unsigned) {
		super();
		this.guard = guard;
		this.dst = dst;
		this.jumpKind = jumpKind;
		this.offsetIP_unsigned = offsetIP_unsigned;
		this.tag = VexStatementType.Ist_Exit;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {

		if (jumpKind == VexJumpKind.Ijk_NoDecode)
			return null;

		ComputationNode guardNode = guard.getNode(graph, this.ina);
		ComputationNode dstNode = graph.getConstant(dst);
		ComputationNode ip = graph.getReg(offsetIP_unsigned, graph.arch.type.defaultTypte());
		// ComputationNode newIp = graph.createCondition(guardNode, dstNode,
		// ip);
		// graph.assignValue(newIp, ip, true);
		graph.registerExit(guardNode, dstNode, ip);
		return null;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		guard.updateTmpOffset(newOffset);
	}

	@Override
	public String toStr(VexToStrState state) {
		return "if(" + guard.toStr(state) + "==1){" + state.arch.type.getGuestInfo().registerName.get(offsetIP_unsigned)
				+ "=0x" + dst.value + "; " + jumpKind.toString() + ";}";
	}

}
