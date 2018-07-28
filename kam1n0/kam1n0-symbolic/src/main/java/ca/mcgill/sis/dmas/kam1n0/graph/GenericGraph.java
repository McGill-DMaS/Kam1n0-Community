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
package ca.mcgill.sis.dmas.kam1n0.graph;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.microsoft.z3.Context;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.LaplaceBox;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunConfigurable;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;

public abstract class GenericGraph implements Serializable {

	public String funcName = StringResources.STR_EMPTY;
	public String binaryName = StringResources.STR_EMPTY;
	public String blockName = StringResources.STR_EMPTY;
	public long blockId = -1;
	public long functionId = -1;

	private static final long serialVersionUID = -3763409298925817180L;
	private static Logger logger = LoggerFactory.getLogger(GenericGraph.class);

	public Long nextBlkSeq = -1l;

	/**
	 * Store all the computational node mapping. e.g. m_0_v0 -> r_0_v0 (read m_0
	 * version 0 to register r_0 version 0). t_0 -> r_0_v1 (read tmp value t_0
	 * to register r_0 version 1). Noted that tmp value will have only one input
	 * thus we don't need to maintain different versions.
	 */
	public HashMap<String, ComputationNode> nodes = new HashMap<>();
	public VexArchitecture arch;

	@JsonCreator
	public GenericGraph() {

	}

	public GenericGraph(GenericGraph graph, boolean linkNode) {
		super();
		this.funcName = graph.funcName;
		this.binaryName = graph.binaryName;
		this.blockName = graph.blockName;
		this.blockId = graph.blockId;
		this.functionId = graph.functionId;
		this.nextBlkSeq = graph.nextBlkSeq;
		this.arch = graph.arch;
		if (linkNode)
			this.nodes = graph.nodes;
	}

	public GenericGraph(String funcName, String binaryName, String blockName, long blockId, long functionId,
			Long nextBlkSeq, HashMap<String, ComputationNode> nodes, VexArchitecture arch) {
		super();
		this.funcName = funcName;
		this.binaryName = binaryName;
		this.blockName = blockName;
		this.blockId = blockId;
		this.functionId = functionId;
		this.nextBlkSeq = nextBlkSeq;
		this.nodes = nodes;
		this.arch = arch;
	}

	public GenericGraph(@JsonProperty("architectureType") HashMap<String, ComputationNode> nodes,
			@JsonProperty("architectureType") VexArchitecture type) {
		this.arch = type;
		this.nodes = nodes;
	}

	@JsonIgnore
	public List<ComputationNode> getInputNodes() {
		return nodes.values().stream().filter(node -> node.parents.size() < 1).collect(Collectors.toList());
	}

	@JsonIgnore
	public List<ComputationNode> getOutputNodes() {
		return nodes.values().stream().filter(node -> {

			if (node.isLatest) {
				if (!arch.type.getGuestInfo().isGeneralReg(node))
					return false;
				if (node.parents.size() < 1)
					return false;
				if (node.children.stream().map(nodes::get).filter(child -> child != null && (!child.isOperation()))
						.findAny().isPresent())
					return false;
				else
					return true;
			} else {
				if (node.children.size() < 1) {
					if (node.parents.size() < 1)
						return false;
					else
						return true;
				} else
					return false;
			}

		}).collect(Collectors.toList());
	}

	@JsonIgnore
	public void debugPrint() {
		// getExpressions(nodes.values(),
		// true).stream().forEach(System.out::println);
		TreeMap<String, ComputationNode> sortedNodes = new TreeMap<>();
		nodes.values().forEach(node -> sortedNodes.put(node.varName, node));
		sortedNodes.values().stream().map(node -> {
			String expr = StringResources.STR_EMPTY;
			if (node.isMem() && node.parents.size() > 0 && node.parents.get(0) != null) {
				expr = node.varName + " [" + node.getParents(nodes).get(0).sExpression(nodes) + "]v" + node.version
						+ " <- " + node.sExpression(nodes);
			} else {
				expr = node.varName + " <- " + node.sExpression(nodes);
			}
			expr = expr + " Links:" + node.toString();
			return expr;
		}).forEach(System.out::println);
		;
	}

	@JsonIgnore
	public void print() {
		getExpressions(getOutputNodes(), false).stream().forEach(System.out::println);
	}

	@JsonIgnore
	public List<String> getExpressions(Collection<ComputationNode> cNodes, boolean debug) {
		return cNodes.stream().map(node -> {
			String expr = StringResources.STR_EMPTY;
			if (node.isMem() && node.parents.size() > 0 && node.parents.get(0) != null) {
				expr = "[" + node.getParents(nodes).get(0).sExpression(nodes) + "]v" + node.version + " <- "
						+ node.sExpression(nodes);
			} else {
				expr = node.varName + " <- " + node.sExpression(nodes);
			}
			if (debug)
				expr = expr + " Links:" + node.toString();
			return expr;
		}).filter(str -> str != null).collect(Collectors.toList());
	}

	@JsonIgnore
	public RunConfigurable toConfigurable(Context ctx) {
		RunConfigurable graph = new RunConfigurable(ctx, this);
		return graph;
	}

	@JsonIgnore
	public RunConfigurable toConfigurable(LaplaceBox box) {
		return this.toConfigurable(box.ctx);
	}

	@JsonIgnore
	public LogicGraphVisualStruct visualize(String id_prefix, String name) {
		LogicGraphVisualStruct struct = new LogicGraphVisualStruct();
		nodes.values().stream().forEach(node -> {
			VisualNode vnode = new VisualNode(node, arch.type, id_prefix);
			struct.nodes.add(vnode);
			struct.varNameToNodeMap.put(node.varName, vnode);
		});
		for (ComputationNode node : nodes.values()) {
			List<ComputationNode> parents = node.getParents(nodes);
			if (parents.size() > 0) {
				for (ComputationNode prt : parents) {
					if (prt != null)
						if (!nodes.containsKey(prt.varName)) {
							logger.error("Target not in the nodes: {} -> {}", prt.varName, node.varName);
						} else {
							VisualLink lnk = new VisualLink(prt.varName, node.varName, id_prefix);
							struct.links.add(lnk);
						}
				}
			}
		}

		struct.inputs = new VisualNode();
		struct.inputs.id = id_prefix + "_input_stage";
		struct.inputs.content.add(name + ": Input Stage");
		struct.outputs = new VisualNode();
		struct.outputs.id = id_prefix + "_output_stage";
		struct.outputs.content.add(name + ": Output Stage");

		List<ComputationNode> inputNodes = this.getInputNodes();
		List<ComputationNode> outputNodes = this.getOutputNodes();

		// getExpressions(outputNodes,
		// false).forEach(struct.outputs.content::add);
		// getRunnable().run(0x02a9l).get(0).toStrLst().forEach(struct.outputs.content::add);

		inputNodes.stream().forEach(input -> {
			VisualLink lnk = new VisualLink("input_stage", input.varName, id_prefix);
			struct.links.add(lnk);
		});

		outputNodes.stream().forEach(output -> {
			VisualLink lnk = new VisualLink(output.varName, "output_stage", id_prefix);
			struct.links.add(lnk);
		});

		if (inputNodes.size() == 0 || outputNodes.size() == 0) {
			VisualLink lnk = new VisualLink("input_stage", "output_stage", id_prefix);
			struct.links.add(lnk);
		}

		return struct;
	}

	public static class LogicGraphVisualStruct {

		public LogicGraphVisualStruct() {
		}

		public VisualNode inputs;
		public VisualNode outputs;

		public ArrayList<VisualNode> nodes = new ArrayList<>();
		public ArrayList<VisualLink> links = new ArrayList<>();

		public HashMap<String, VisualNode> varNameToNodeMap = new HashMap<>();
		// use for visualize concrete value of each variable
	}

	public static class VisualNode implements Serializable {
		private static final long serialVersionUID = 567777421715795571L;
		public String id;
		public List<String> content = new ArrayList<>();

		public VisualNode() {
		}

		public VisualNode(ComputationNode node, VexArchitectureType architectureType, String id_prefix) {
			id = id_prefix + "_" + node.varName;
			content.add(node.desp(architectureType));
		}
	}

	public static class VisualLink implements Serializable {
		private static final long serialVersionUID = -3012737921524201819L;
		public String source, target;

		public VisualLink(String src, String tar, String id_prefix) {
			source = id_prefix + "_" + src;
			target = id_prefix + "_" + tar;
		}

		public VisualLink() {

		}

	}

}
