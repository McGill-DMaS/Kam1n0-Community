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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.DirtyCalls;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexCall;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.StmDirtyEffect;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;

public class StmDirty extends VexStatement {

	private static Logger logger = LoggerFactory.getLogger(StmDirty.class);

	public VexCall cee;

	public VexExpression guard;
	public List<VexExpression> args;
	public int tmp_unsigned;

	public StmDirtyEffect mFx;
	public VexExpression mAddr;
	public int mSize;

	public ArrayList<StmDirtyFxStat> fxStates;

	@JsonIgnore
	private boolean tmpUpdated = false;

	public StmDirty(@JsonProperty("cee") VexCall cee, @JsonProperty("guard") VexExpression guard,
			@JsonProperty("args") List<VexExpression> args, @JsonProperty("tmp_unsigned") int tmp_unsigned,
			@JsonProperty("mFx") StmDirtyEffect mFx, @JsonProperty("mAddr") VexExpression mAddr,
			@JsonProperty("mSize") int mSize, @JsonProperty("fxStates") ArrayList<StmDirtyFxStat> fxStates) {
		super();
		this.cee = cee;
		this.guard = guard;
		this.args = args;
		this.tmp_unsigned = tmp_unsigned;
		this.mFx = mFx;
		this.mAddr = mAddr;
		this.mSize = mSize;
		this.fxStates = fxStates;
		this.tag = VexStatementType.Ist_Dirty;
	}

	@Override
	public void updateTmpOffset(int newOffset) {
		if (guard != null)
			guard.updateTmpOffset(newOffset);
		if (args != null)
			args.stream().forEach(arg -> arg.updateTmpOffset(newOffset));
		if (mAddr != null)
			mAddr.updateTmpOffset(newOffset);

		if (!tmpUpdated) {
			tmp_unsigned += newOffset;
			tmpUpdated = true;
		}
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		// assuming guard is true. Consider implementation.
		if (!guard.getNode(graph, ina).isConst()) {
			logger.error("Assuming guad for dirty is alwasys true. consider implementing. addr 0x{}", ina);
		}
		// logger.info("Type: {}", graph.tmpVarTypes.get(tmp_unsigned));
		if (cee != null) {
			if (!DirtyCalls.implemented(cee.name)) {
				logger.error("Not-implemented dirty call: {}. Consider implementaion.", cee.name);
				return null;
			} else {
				DirtyCalls.call(this, graph);
				return null;
			}
		} else
			return null;

	}

	@Override
	public String toStr(VexToStrState state) {
		return "if(" + guard.toStr(state) + "){ t" + tmp_unsigned + "=" + cee.name + "("
				+ StringResources.JOINER_TOKEN_CSV
						.join(args.stream().map(arg -> arg.toStr(state)).collect(Collectors.toList()))
				+ ")}";
	}

}
