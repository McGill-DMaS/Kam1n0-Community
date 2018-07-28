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
package ca.mcgill.sis.dmas.kam1n0.symbolic;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.Assignment;

public class Symbol {

	public ComputationNode cNode;
	@JsonIgnore
	public SimNode sNode;

	public Set<Symbol> leaves = new HashSet<>();

	public static final String VAR_IDENTIFIER = "var";
	public static final String VAR_ITE = "ite";

	@Override
	public String toString() {
		return cNode.varName;
	}

	public List<Symbol> getConstants() {
		return leaves.stream().filter(sym -> sym.cNode.isConst()).collect(Collectors.toList());
	}

	public ComputationNode getcNode() {
		return cNode;
	}

	public void setcNode(ComputationNode cNode) {
		this.cNode = cNode;
	}

	@JsonIgnore
	public SimNode getsNode() {
		return sNode;
	}

	@JsonIgnore
	public void setsNode(SimNode sNode) {
		this.sNode = sNode;
	}

	public Symbol(ComputationNode cNode, SimNode sNode, Set<Symbol> leaves) {
		super();
		this.cNode = cNode;
		this.sNode = sNode;
		this.leaves = leaves;
	}

	public Symbol(ComputationNode cNode, SimNode sNode) {
		super();
		this.cNode = cNode;
		this.sNode = sNode;
	}

	public Symbol() {
	}

	public Symbol substitue(List<Assignment> inputs) {
		return new Symbol(this.cNode, sNode.setValues(inputs), this.leaves);
	}
}