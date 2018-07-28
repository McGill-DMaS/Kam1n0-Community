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
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmIMark extends VexStatement {

	public long addr_unsigned;
	public int len_unsigned;
	public byte delta_unsigned;

	public String dat = StringResources.STR_EMPTY;

	public StmIMark(@JsonProperty("addr_unsigned") long addr_unsigned, @JsonProperty("len_unsigned") int len_unsigned,
			@JsonProperty("delta_unsigned") byte delta_unsigned) {
		super();
		this.addr_unsigned = addr_unsigned;
		this.len_unsigned = len_unsigned;
		this.delta_unsigned = delta_unsigned;
		this.tag = VexStatementType.Ist_IMark;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		graph.memory.addData(addr_unsigned, dat);
		return null;
	}

	@Override
	public void updateTmpOffset(int newOffset) {

	}

	@Override
	public String toStr(VexToStrState state) {
		return "- - - " + (state.arch.type == VexArchitectureType.VexArchARM
				? (delta_unsigned == 1 ? "Thumb Mode" : "ARM Mode") : "")
				+ (state.simplifyTmpVariables ? " - - - simplified vex code:" : "");
	}

}
