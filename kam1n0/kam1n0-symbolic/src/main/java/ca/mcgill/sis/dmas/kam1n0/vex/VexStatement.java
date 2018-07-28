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
package ca.mcgill.sis.dmas.kam1n0.vex;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmDirty;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class VexStatement {

	private static Logger logger = LoggerFactory.getLogger(VexStatement.class);

	public VexStatementType tag;
	public long ina = 0;

	public abstract void updateTmpOffset(int newOffset);

	public static class VexToStrState {
		public VexArchitecture arch;
		public HashMap<Integer, String> tmpMemory = new HashMap<>();
		public boolean simplifyTmpVariables = false;
		public boolean ignorePC = false;
		public boolean regularRegOnly = false;

		public VexToStrState(VexArchitecture arch, boolean simplify) {
			this.arch = arch;
			this.simplifyTmpVariables = simplify;
			this.ignorePC = simplify;
			this.regularRegOnly = simplify;
		}
	}

	public abstract String toStr(VexToStrState state);

	public ComputationNode translate(ComputationGraph graph) {
		logger.error(
				"Not implemented expression interpretator for expression type: {} at addr 0x{}. Consider implementing.",
				tag, Long.toHexString(ina));

		if (tag.equals(VexStatementType.Ist_Dirty)) {
			StmDirty stm = (StmDirty) this;
			logger.info("Consider implementing {}", stm.cee.name);
		}

		// throw new NotImplementedException();
		return null;
	}

}
