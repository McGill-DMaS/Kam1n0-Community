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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.SymbolicCCalls;
import ca.mcgill.sis.dmas.kam1n0.symbolic.SymbolicCCalls.CCallFunction;
import ca.mcgill.sis.dmas.kam1n0.vex.SimplifiedCCalls;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexCall;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

public class ExCCall extends VexExpression {

	private static Logger logger = LoggerFactory.getLogger(ExCCall.class);

	public VexCall cee;
	public VexVariableType type;
	public ArrayList<VexExpression> args;

	public ExCCall(@JsonProperty("cee") VexCall callee, @JsonProperty("type") VexVariableType type,
			@JsonProperty("args") ArrayList<VexExpression> args) {
		super();
		this.cee = callee;
		this.type = type;
		this.args = args;
		this.tag = VexExpressionType.Iex_CCall;
	}

	@Override
	public ComputationNode getNode(ComputationGraph graph, long ina) {
		List<ComputationNode> argns = args.stream().map(arg -> arg.getNode(graph, ina)).collect(Collectors.toList());

		if (cee != null && SimplifiedCCalls.implemented(cee.name)) {
			return SimplifiedCCalls.call(cee.name, graph, type, argns);
		} else {

			if (cee.name != null && !SymbolicCCalls.implemented(cee.name)) {
				logger.error("Not-implemented ccall: {}  SE:'0x{}' Consider implementaion.", cee.name,
						Long.toHexString(ina));
			}

			ComputationNode node = new ComputationNode(this, graph.tmpVarTypes);
			node.ccall_oprName = cee.name;
			graph.addComputationNode(node, argns);
			return node;
		}

	}

	@Override
	public void updateTmpOffset(int newOffset) {
		args.forEach(arg -> arg.updateTmpOffset(newOffset));
	}

	@Override
	public String toStr(VexToStrState state) {
		return cee.name + "(" + StringResources.JOINER_TOKEN_CSV
				.join(args.stream().map(arg -> arg.toStr(state)).collect(Collectors.toList())) + ")";
	}

}
