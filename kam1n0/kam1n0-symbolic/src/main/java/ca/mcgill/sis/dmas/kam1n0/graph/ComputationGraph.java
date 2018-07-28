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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ArrayListMultimap;

import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph.NodeType;
import ca.mcgill.sis.dmas.kam1n0.vex.VEXIRBB;
import ca.mcgill.sis.dmas.kam1n0.vex.VexConstant;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

/**
 * The computation graph of one basic block. Its size may be very large. Try not
 * loading everything when conducting analysis if you use disk datastore.
 * 
 * @author dingm
 *
 */
public class ComputationGraph extends GenericGraph {

	private static final long serialVersionUID = 7740185400575245201L;

	static Logger logger = LoggerFactory.getLogger(ComputationGraph.class);

	public List<VexVariableType> tmpVarTypes = new ArrayList<>();

	/**
	 * Store different versions of the register. when one tries to write to a
	 * register, check: if(this register has been read before): create new
	 * version; if(this register has not been read before): update the latest
	 * version's value; if(this register has not been used before): create
	 * registerKey->version0
	 */
	public ArrayListMultimap<String, ComputationNode> regVersionMap = ArrayListMultimap.create();

	/**
	 * Store constants. Same constant value will have the same computational
	 * node.
	 */
	public HashMap<String, ComputationNode> constants = new HashMap<>();

	/**
	 * Static memory layout. Checking whether two memory values refer to the
	 * same one using their statically resolved sExpression. e.g. m_0_v0 = [Add
	 * r_0_v0 0x00c] will be the same to m_1_v0 = [Add r_0_v0 0x00c]. [Add
	 * r_0_v1 0x00c] and [Add r_0_v3 0x00c] will be two different memory
	 * variable. To resolve them we need dynamic memory layout which resolves
	 * the values of r_0_v1 and r_0_v3 at run time.
	 */
	public StaticMemoryLayout memory;

	private int consInd = 0;
	private int oprInd = 0;

	public final static String constantPrefix = "c_";
	public final static String registerPrefix = "r_";
	public final static String tempVarPrefix = "t_";
	public final static String memPrefix = "m_";

	public final static String oprPrefix = "o_";

	public static enum NodeType {
		mem, var, calculate, condition
	}

	static boolean debug = false;

	@JsonCreator
	public ComputationGraph() {
	}

	public ComputationGraph(ComputationGraph graph, boolean linkGraph) {
		super(graph, linkGraph);
		this.consInd = graph.consInd;
		this.oprInd = graph.oprInd;
		this.constants.putAll(graph.constants);
		this.nextBlkSeq = graph.nextBlkSeq;
		memory = new StaticMemoryLayout(this.arch.type);
	}

	public static ComputationGraph translate(VEXIRBB irbb) {
		ComputationGraph graph = new ComputationGraph();
		graph.arch = irbb.architecture;
		graph.binaryName = irbb.binaryName;
		graph.funcName = irbb.functionName;
		graph.blockName = irbb.blockName;
		graph.functionId = irbb.functionId;
		graph.blockId = irbb.blockId;
		graph.tmpVarTypes = irbb.types;
		graph.memory = new StaticMemoryLayout(irbb.architecture.type);

		Counter counter = Counter.zero();
		irbb.statements.stream().forEach(stm -> {
			if (debug) {
				System.out.println();
				System.out.println("* * * * * * * * * * * * * * * * * * * * * * * * * * * *");
				try {
					System.out.println((new ObjectMapper()).writerWithDefaultPrettyPrinter().writeValueAsString(stm));
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			stm.translate(graph);
			if (debug) {
				counter.inc();
				System.out.println(graph.nodes.size() + " " + counter.getVal() + "/" + irbb.statements.size());
				System.out.println("- - - - - - - - - ");
				TreeMap<String, ComputationNode> tree = new TreeMap<>();
				tree.putAll(graph.nodes);
				tree.values().stream()
						.map(node -> node.varName + " = " + node.toString() + " $ " + node.traverseId(graph.nodes, 10))
						.forEach(System.out::println);
			}
		});

		if (irbb.next != null && irbb.offsetsIP != -1) {
			graph.registerExit(null, irbb.next.getNode(graph, -1),
					graph.getReg(irbb.offsetsIP, graph.arch.type.defaultTypte()));
		}
		graph.mergeExitPoint();
		graph.nextBlkSeq = irbb.getSequentialNextAddr();

		return graph;
	}

	@JsonIgnore
	public ComputationNode getConstant(int size, long val) {
		return getConstant(size, Long.toHexString(val));
	}

	@JsonIgnore
	public ComputationNode getConstant(int size, int val) {
		return getConstant(size, Integer.toHexString(val));
	}

	@JsonIgnore
	public ComputationNode getConstant(int size, String hex) {
		return getConstant(VexConstant.createVexConstantFromSize(size, hex));
	}

	@JsonIgnore
	public ComputationNode getConstant(VexConstant constant) {

		ComputationNode constantNode = constants.get(constant.value);
		if (constantNode == null) {
			TypeInformation tp = new TypeInformation();
			tp.outputType = constant.type.toVariableType();
			tp.argType.add(constant.type.toVariableType());
			constantNode = new ComputationNode(NodeType.var, tp);
			constantNode.constant = constant;
			constantNode.valType = new TypeInformation();
			constantNode.valType.outputType = constant.type.toVariableType();
			constantNode.valType.argType.add(constant.type.toVariableType());
			constantNode.varName = constantPrefix + Integer.toString(consInd) + ":0x" + constant.value;
			constantNode.index = consInd;
			consInd++;
			constants.put(constant.value, constantNode);
		}
		nodes.put(constantNode.varName, constantNode);
		return constantNode;
	}

	@JsonIgnore
	public ComputationNode getReg(String name, VexVariableType type) {
		ComputationNode node = getReg(arch.type.getGuestInfo().getRegOffset(name), type);
		if (node == null) {
			logger.error("Failed to get node for register {} of type {}", name, type);
			return null;
		}
		return node;
	}

	@JsonIgnore
	public ComputationNode getRegUnconstrained(long ina, String name, VexVariableType type) {
		TypeInformation tp = new TypeInformation();
		tp.outputType = type;
		tp.argType.add(type);
		ComputationNode node = new ComputationNode(NodeType.var, tp);
		node.varName = name + "_" + Long.toHexString(ina);
		node.version = 0;
		nodes.put(node.varName, node);
		return node;
	}

	@JsonIgnore
	public ComputationNode getReg(int offset, VexVariableType type) {
		String realName = arch.type.getGuestInfo().registerName.get(offset);
		String requestedName;
		if (realName == null)
			requestedName = registerPrefix + offset;
		else
			requestedName = registerPrefix + realName;
		List<ComputationNode> nodeL = regVersionMap.get(requestedName);
		if (nodeL.size() == 0) {
			// create a new register variable and add to version map
			TypeInformation tp = new TypeInformation();
			tp.outputType = type;
			tp.argType.add(type);
			ComputationNode node = new ComputationNode(NodeType.var, tp);
			node.index = offset;
			node.varName = requestedName + "_v0";
			node.reqName = requestedName;
			node.version = 0;
			nodes.put(node.varName, node);
			regVersionMap.put(requestedName, node);
			return node;
		} else
			// return the latest version of that register
			return nodeL.get(nodeL.size() - 1);
	}

	@JsonIgnore
	public boolean isRegLatest(ComputationNode reg) {
		if (!reg.isRegister())
			return false;
		int offset = reg.index;
		String realName = arch.type.getGuestInfo().registerName.get(offset);
		String requestedName;
		if (realName == null)
			requestedName = registerPrefix + offset;
		else
			requestedName = registerPrefix + realName;
		List<ComputationNode> nodeL = regVersionMap.get(requestedName);
		if (reg.version == nodeL.size() - 1)
			return true;
		return false;
	}

	@JsonIgnore
	public ComputationNode addComputationNode(ComputationNode operationNode, List<ComputationNode> inputs) {
		String varName = oprPrefix + oprInd;
		operationNode.varName = varName;
		operationNode.index = oprInd;
		nodes.put(operationNode.varName, operationNode);
		oprInd++;
		operationNode.parents.addAll(inputs.stream().map(input -> input.varName).collect(Collectors.toList()));
		inputs.stream().forEach(input -> input.children.add(operationNode.varName));
		return operationNode;
	}

	@JsonIgnore
	public ComputationNode addComputationNode(ComputationNode operationNode, ComputationNode... inputs) {
		return addComputationNode(operationNode, Arrays.asList(inputs));
	}

	@JsonIgnore
	public ComputationNode getTmpVar(int tmpId) {
		String requestedName = tempVarPrefix + tmpId;
		ComputationNode node = nodes.get(requestedName);
		if (node == null) {
			TypeInformation tp = new TypeInformation();
			tp.argType.add(tmpVarTypes.get(tmpId));
			tp.outputType = tmpVarTypes.get(tmpId);
			node = new ComputationNode(NodeType.var, tp);
			node.index = tmpId;
			node.varName = requestedName;
			node.reqName = requestedName;
			node.version = 0;
			nodes.put(requestedName, node);
		}
		return node;
	}

	@JsonIgnore
	public void assignValue(ComputationNode from, ComputationNode to) {
		assignValue(from, to, false);
	}

	@JsonIgnore
	public void assignValue(ComputationNode from, ComputationNode to, boolean forceNewVersion) {

		if (from == null || to == null) {
			logger.info("Error ssigning {} to {}", from, to);
			return;
		}

		// tmp var can have one input and multiple output
		if (to.isTmp()) {
			if (to.parents.size() > 0)
				logger.error(
						"VEX ERROR: {} should only have one input. but it already has {} as input before assigning {}; Ignoring this error.",
						to.varName, to.parents, from.varName);
			from.children.add(to.varName);
			to.parents.add(from.varName);
			return;
		}

		// it is fine. we override the type information of the original node so
		// we skip this condition checking
		// if (!from.valType.outputType.equals(to.valType.argType.get(0)))
		// logger.error("I/O size not matched in value assignment from {}:{} to
		// {}:{}", from.varName, from.valType,
		// to.varName, to.valType);

		// * a register can have one input and multiple output
		// * input can be updated if it does not have output
		// * if it has output, the update should create a new version, following
		// calls will use the new version
		if (to.isRegister()) {
			if (to.children.size() > 0 || forceNewVersion) {
				// contaminated
				// create new version
				List<ComputationNode> nodeL = regVersionMap.get(to.reqName);
				ComputationNode node = new ComputationNode(NodeType.var, to.valType);
				node.varName = to.reqName + "_v" + nodeL.size();
				node.version = nodeL.size();
				node.reqName = to.reqName;
				node.index = to.index;
				if (!from.valType.outputType.equals(to.valType.argType.get(0))) {
					node.valType.argType.clear();
					node.valType.argType.add(from.valType.outputType);
					node.valType.outputType = from.valType.outputType;
				}
				nodes.put(node.varName, node);
				regVersionMap.put(node.reqName, node);
				to = node;
				// assign value
				from.children.add(to.varName);
				to.parents.add(from.varName);
			} else {
				// update value
				from.children.add(to.varName);
				if (to.parents.size() == 0)
					to.parents.add(from.varName);
				else
					to.parents.set(0, from.varName);
				if (!from.valType.outputType.equals(to.valType.argType.get(0))) {
					to.valType.argType.clear();
					to.valType.argType.add(from.valType.outputType);
					to.valType.outputType = from.valType.outputType;
				}
			}

			return;
		}

		if (to.isMem()) {
			if (to.parents.size() > 2)
				logger.error(
						"VEX ERROR: memory {} should only have max two inputs (addr, value). but it already has {} as input before assigning {}",
						from.varName, from.parents, to.varName);
			if (to.children.size() > 1)
				logger.error(
						"VEX ERROR: contaminating a memory variable {}. It has been assigned to {} but now it is being modify. A new value should be created.",
						to.varName, to.children);
			from.children.add(to.varName);
			to.parents.add(from.varName);
			return;
		}

		logger.error("NEVER SHOULD REACH HERE. {} vs {}", from.varName, to.varName);

	}

	@JsonIgnore
	public ComputationNode createCondition(ComputationNode condition, int ifTrue, int ifFalse) {
		return createCondition(condition, getConstant(arch.type.defaultTypte().numOfBit(), ifTrue),
				getConstant(arch.type.defaultTypte().numOfBit(), ifFalse));
	}

	@JsonIgnore
	public ComputationNode createCondition(ComputationNode condition, ComputationNode ifTrue, ComputationNode ifFalse) {
		TypeInformation typeInfo = new TypeInformation();
		typeInfo.argType.addAll(
				Arrays.asList(condition.valType.outputType, ifTrue.valType.outputType, ifFalse.valType.outputType));
		typeInfo.outputType = ifTrue.valType.outputType;
		ComputationNode node = new ComputationNode(NodeType.condition, typeInfo);
		this.addComputationNode(node, condition, ifTrue, ifFalse);
		return node;
	}

	@JsonIgnore
	public ComputationNode createMemVar(ComputationNode addr, VexVariableType type, VexEndnessType endness, int vIndex,
			int version) {
		TypeInformation typeInformation = new TypeInformation();
		typeInformation.outputType = type;
		typeInformation.argType.add(type);
		ComputationNode node = new ComputationNode(NodeType.mem, typeInformation);
		node.parents.add(addr.varName);
		addr.children.add(node.varName);
		node.varName = memPrefix + (vIndex) + "_v" + version;
		node.index = vIndex;
		node.version = version;
		nodes.put(node.varName, node);
		return node;
	}

	@JsonIgnore
	private ArrayList<EntryTriplet<ComputationNode, ComputationNode, ComputationNode>> exitPoints = new ArrayList<>();

	@JsonIgnore
	public void registerExit(ComputationNode condition, ComputationNode value, ComputationNode pc) {
		if (value.isConst())
			value.isCntAddr = true;
		exitPoints.add(new EntryTriplet<ComputationNode, ComputationNode, ComputationNode>(condition, value, pc));
	}

	@JsonIgnore
	public void mergeExitPoint() {
		if (exitPoints.size() < 1)
			return;
		Set<Integer> offsets = exitPoints.stream().map(point -> point.value2.index).collect(Collectors.toSet());
		if (offsets.size() > 1) {
			logger.error("More than 1 pc counter registers in exit points. consider implementing support.");
			return;
		}
		Integer offset = offsets.stream().findAny().get();
		if (exitPoints.size() > 0) {
			ComputationNode defaultVal = null;
			List<EntryTriplet<ComputationNode, ComputationNode, ComputationNode>> ls = exitPoints.stream()
					.filter(point -> point.value0 == null).collect(Collectors.toList());
			// only want the last one.
			if (ls.size() > 0)
				defaultVal = ls.get(ls.size() - 1).value1;
			else
				defaultVal = getReg(offset, arch.type.defaultTypte());
			List<ComputationNode> parents = defaultVal.getParents(this);
			for (ComputationNode parent : parents) {
				while (parent.type == NodeType.var && parent.parents.size() == 1) {
					parent = parent.getParents(this).get(0);
					if (parent == null)
						break;
				}
				// well, we don't know why some constants like 0x01 appears
				// here.
				// so we restrict that it can has only one children.
				// we assume that a bunching address wont be used twice in
				// a single block
				if (parent.isConst() && parent.children.size() == 1)
					parent.isCntAddr = true;
			}

			for (EntryTriplet<ComputationNode, ComputationNode, ComputationNode> point : exitPoints) {
				if (point.value0 == null)
					continue;
				defaultVal = createCondition(point.value0, point.value1, defaultVal);
			}
			ComputationNode pc = getReg(offset, arch.type.defaultTypte());
			assignValue(defaultVal, pc);
		}
	}

	public LogicGraph simplify() {
		HashSet<String> toBeSimplified = new HashSet<>();
		nodes.keySet().stream().filter(key -> {
			ComputationNode node = nodes.get(key);

			if (isRegLatest(node)) {
				if (!arch.type.getGuestInfo().isGeneralReg(node))
					return false;
				if (node.parents.size() < 1)
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

		}).forEach(key -> {
			ComputationNode node = nodes.get(key);
			if (!node.isTmp())
				toBeSimplified.add(node.varName);
		});

		ComputationGraph newGraph = new ComputationGraph(this, false);
		toBeSimplified.stream().forEach(key -> {
			ComputationNode resolvedNode = nodes.get(key).resolve(this, newGraph, true, true);
			newGraph.nodes.put(key, resolvedNode);
		});

		// clean
		Set<String> empt = newGraph.nodes.values().stream().filter(
				node -> node.getChildren(newGraph.nodes).size() < 1 && node.getParents(newGraph.nodes).size() < 1)
				.map(node -> node.varName).collect(Collectors.toSet());
		empt.stream().forEach(newGraph.nodes::remove);

		newGraph.cleanOutput();
		newGraph.cleanInput();

		return new LogicGraph(newGraph);

	}

	private void cleanOutput() {
		HashSet<String> toBeRemoved = new HashSet<>();
		for (ComputationNode node : this.getOutputNodes()) {
			// skip direct assignment (var/mem -> var/mem). there are too much
			// of them.

			// if (node.depth == 1) {
			if (node.children.size() < 1) {
				ComputationNode parent;
				if (node.type == NodeType.mem)
					parent = node.getParents(this).get(1);
				else
					parent = node.getParents(this).get(0);
				if (parent.depth == 0) {
					if (parent.type == NodeType.var || parent.type == NodeType.mem)
						if (!parent.isConst())
							toBeRemoved.add(node.varName);
				}
			}
			// }

		}
		toBeRemoved.forEach(this.nodes::remove);
	}

	private void cleanInput() {
		Set<String> toBeRemoved = getInputNodes().stream()
				.filter(node -> node.getChildren(this).stream().filter(chld -> chld != null).count() == 0)
				.map(node -> node.varName).collect(Collectors.toSet());
		toBeRemoved.stream().forEach(this.nodes::remove);
	}

}
