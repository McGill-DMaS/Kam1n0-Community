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
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmAbiHint extends VexStatement {

	public VexExpression base;
	public int len;
	public VexExpression nia;

	public StmAbiHint(@JsonProperty("base") VexExpression base, @JsonProperty("len") int len,
			@JsonProperty("nia") VexExpression nia) {
		super();
		this.base = base;
		this.len = len;
		this.nia = nia;
		this.tag = VexStatementType.Ist_AbiHint;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		return null;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		base.updateTmpOffset(newOffset);
		nia.updateTmpOffset(newOffset);
	}

	@Override
	public String toStr(VexToStrState state) {
		return "AbiHint";
	}
}
