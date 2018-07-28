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
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmMBE extends VexStatement {
	public boolean imbe_fence_or_cancelreservation;

	public StmMBE(@JsonProperty("imbe_fence_or_cancelreservation") boolean imbe_fence_or_cancelreservation) {
		super();
		this.imbe_fence_or_cancelreservation = imbe_fence_or_cancelreservation;
		this.tag = VexStatementType.Ist_MBE;
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		return null;
	}

	@Override
	public void updateTmpOffset(int newOffset) {

	}

	@Override
	public String toStr(VexToStrState state) {
		return "StmMBE:" + imbe_fence_or_cancelreservation;
	}

}
