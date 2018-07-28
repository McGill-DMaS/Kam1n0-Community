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
package ca.mcgill.sis.dmas.kam1n0.symbolic.run;

import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microsoft.z3.Context;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.graph.GenericGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.LogicGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph.NodeType;
import ca.mcgill.sis.dmas.kam1n0.symbolic.SimNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.Symbol;
import ca.mcgill.sis.dmas.kam1n0.symbolic.Z3Box;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.Attribute;

public class RunConfigurable extends GenericGraph {

	private static Logger logger = LoggerFactory.getLogger(RunConfigurable.class);

	private static final long serialVersionUID = 3977127981017604515L;

	public HashMap<String, Symbol> outputSymbols = new HashMap<>();
	public TreeMap<String, Symbol> inputSymbols = new TreeMap<>();
	public HashMap<String, Symbol> symbols = new HashMap<>();

	private Z3Box box;

	public RunConfigurable(Context ctx, GenericGraph graph) {
		super(graph, true);
		box = new Z3Box(ctx, graph.arch.type, graph.blockName);
		translateAll(null);

	}

	public List<RunConfiguration> getConfigurations(Collection<String> varNames) {
		return varNames.stream().map(varName -> getConfiguration(varName)).filter(conf -> conf != null)
				.collect(Collectors.toList());
	}

	public RunConfiguration getConfiguration(String varName) {
		Symbol sym = outputSymbols.get(varName);
		if (sym == null)
			return null;
		return getConfiguration(sym);
	}

	public List<RunConfiguration> getConfigurations(boolean all) {
		if (all) {
			return symbols.values().stream().map(this::getConfiguration).collect(Collectors.toList());
		} else {
			return outputSymbols.values().stream().map(this::getConfiguration).collect(Collectors.toList());
		}
	}

	public RunConfiguration getConfiguration(Symbol sym) {
		if (sym == null)
			return null;
		RunConfiguration conf = new RunConfiguration();
		conf.inputAssignments = sym.leaves.stream().filter(in -> in != null && !in.cNode.isConst()).map(in -> {
			Assignment pair = new Assignment(in, Long.toHexString(0));
			return pair;
		}).collect(Collectors.toList());
		conf.outputSymbol = sym;
		conf.configurable = this;
		return conf;
	}

	private Symbol translate(ComputationNode cNode) {
		// try {
		Symbol sym = symbols.get(cNode.varName);
		if (sym != null)
			return sym;

		switch (cNode.type) {
		case var: {
			if (cNode.parents.size() == 1) {
				Symbol inm = translate(cNode.getParents(this).get(0));
				TreeSet<Symbol> ordredLeaves = new TreeSet<Symbol>(
						(sym1, sym2) -> sym1.cNode.varName.compareTo(sym2.cNode.varName));
				ordredLeaves.addAll(inm.leaves);
				sym = new Symbol(cNode, inm.sNode, ordredLeaves);
			} else if (cNode.parents.size() == 0) {
				SimNode exp;
				if (cNode.isConst() && cNode.constant != null) {
					exp = box.createConstant(cNode.varName, cNode.constant);
					sym = new Symbol(cNode, exp);
					sym.leaves.add(sym);
				} else {
					exp = box.createVar(cNode.varName, cNode.valType.outputType);
					sym = new Symbol(cNode, exp);
					sym.leaves.add(sym);
				}
			} else {
				logger.error("A var node should have no more than one parent: {}", cNode.toString());
			}
			break;
		}
		case mem: {
			if (cNode.parents.size() == 0) {
				SimNode exp = box.createVar(cNode.varName, cNode.valType.outputType);
				sym = new Symbol(cNode, exp);
				sym.leaves.add(sym);
			} else if (cNode.parents.size() == 1) {
				logger.error("The abstracted memory variable {} should have parents of [null,value]. ",
						cNode.toString());
			} else if (cNode.parents.size() == 2 && cNode.parents.get(0) == null) {
				Symbol data = translate(cNode.getParents(this).get(1));
				TreeSet<Symbol> ordredLeaves = new TreeSet<Symbol>(
						(sym1, sym2) -> sym1.cNode.varName.compareTo(sym2.cNode.varName));
				ordredLeaves.addAll(data.leaves);
				sym = new Symbol(cNode, data.sNode, ordredLeaves);
			}
			break;
		}
		case calculate: {
			List<Symbol> args = cNode.getParents(this).stream().map(arg -> translate(arg)).collect(Collectors.toList());
			List<SimNode> exprs = args.stream().filter(arg -> arg != null).map(arg -> arg.sNode)
					.collect(Collectors.toList());
			if (exprs.size() != args.size()) {
				logger.error("There is empty expression in the argument for node {}", cNode.toString());
			} else {
				SimNode exp;
				if (cNode.ccall_oprName != null) {
					exp = box.createCCall(cNode.varName, cNode.ccall_oprName, cNode.valType, exprs);
					sym = new Symbol(cNode, exp);
					sym.leaves.addAll(args.stream().flatMap(arg -> arg.leaves.stream()).collect(Collectors.toList()));
				} else if (cNode.oprType != null) {
					exp = box.createOperation(cNode.oprType, exprs);
					sym = new Symbol(cNode, exp);
					sym.leaves.addAll(args.stream().flatMap(arg -> arg.leaves.stream()).collect(Collectors.toList()));
				} else {
					logger.error("The oprType should be filled for the calculate node " + cNode);
				}
			}
			break;
		}
		case condition: {
			List<Symbol> args = cNode.getParents(this).stream().map(arg -> translate(arg)).collect(Collectors.toList());
			if (args.stream().filter(arg -> arg != null).count() != 3) {
				logger.error("We need three arguments for the if-then-else clause in logic graph. returning null.");
			} else {
				Symbol ifc = args.get(0);
				Symbol thenc = args.get(1);
				Symbol elsec = args.get(2);
				if (ifc == null || thenc == null || elsec == null) {
					logger.error("Type error for the if-then-else clauses.");
				} else {
					SimNode exp = box.createCondition(ifc.sNode, thenc.sNode, elsec.sNode);
					sym = new Symbol(cNode, exp);
					sym.leaves.addAll(args.stream().flatMap(arg -> arg.leaves.stream()).collect(Collectors.toList()));
				}
			}
			break;
		}
		default:
			logger.error("Symbolic translation error (not type) for {} of {}; returning empty.", cNode.varName,
					cNode.type);
			break;
		}
		if (sym != null)
			symbols.put(cNode.varName, sym);
		return sym;
		// } catch (Exception e) {
		// logger.error("Failed to translate " + cNode.desp(arch.type) + "@" +
		// this.blockName + "@" + this.binaryName
		// + ". Parents: " + this.getExpressions(cNode.getParents(this), true),
		// e);
		// return null;
		// }
	}

	private void translateAll(Predicate<ComputationNode> outputSelector) {
		this.symbols.clear();
		this.inputSymbols.clear();
		this.outputSymbols.clear();

		for (ComputationNode node : this.getOutputNodes()) {

			if (outputSelector != null && !outputSelector.test(node)) {
				continue;
			}

			try {
				// Symbol valSym = null;
				//
				// if (node.isMem()) {
				// valSym = translate(nodes.get(node.parents.get(1)));
				//
				// } else {
				// valSym = translate(nodes.get(node.parents.get(0)));
				// } // very important! sort the leaves!
				// TreeSet<Symbol> ordredLeaves = new TreeSet<Symbol>(
				// (sym1, sym2) ->
				// sym1.cNode.varName.compareTo(sym2.cNode.varName));
				// ordredLeaves.addAll(valSym.leaves);
				// Symbol sym = new Symbol(node, valSym.sNode, ordredLeaves);
				Symbol sym = translate(node);
				if (sym == null || sym.sNode == null)
					continue;
				symbols.put(node.varName, sym);
				outputSymbols.put(node.varName, sym);

				// if (sym.leaves.size() != sym.cNode.leaves.size()) {
				// Set<String> set = sym.leaves.stream().map(leaf ->
				// leaf.cNode.varName)
				// .collect(Collectors.toSet());
				// logger.error("{} syms:{} cns:{} s:{} ", sym.cNode.varName,
				// set, sym.cNode.leaves,
				// sym.cNode.sExpression(this.nodes));
				// }

			} catch (Exception e) {
				// logger.error("Failed to translate: " +
				// node.sExpression(this.nodes), e);
			}
		}

		this.getInputNodes().forEach(cnode -> {
			Symbol simNode = symbols.get(cnode.varName);
			if (simNode != null && !simNode.sNode.e.isNumeral())
				inputSymbols.put(cnode.varName, simNode);
		});

	}

	public void print(String suffix) {
		System.out.println(suffix + "#Inputs:");
		inputSymbols.forEach((k, v) -> System.out.println(suffix + k + ": " + v.sNode.e.getSExpr()));
		System.out.println(suffix + "#Outputs:");
		outputSymbols.forEach((k, v) -> System.out.println(suffix + k + ": " + v.sNode.e.getSExpr()));
	}

	public void print() {
		print("");
	}

	public Map<String, Symbol> getInputSimNodes() {
		return this.inputSymbols;
	}

	public Map<String, Symbol> getOutputSimNodes() {
		return this.outputSymbols;
	}

	public int getNumInputs() {
		return this.inputSymbols.size();
	}

	public int getNumOutputs() {
		return this.outputSymbols.size();
	}

}
