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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.sun.org.apache.bcel.internal.generic.I2F;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph.NodeType;
import ca.mcgill.sis.dmas.kam1n0.vex.VexConstant;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexOperation;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexConstantSimplifier;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexConstantSimplifier.VexOperationInJava;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.Attribute;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

public class ComputationNode implements Serializable {

	private static final long serialVersionUID = 4112270073282917513L;
	private static Logger logger = LoggerFactory.getLogger(ComputationNode.class);
	public static final String VAR_IDENTIFIER = "var";
	public static final String VAR_ADDR = "add";
	public static final String VAR_ITE = "ite";

	@JsonCreator
	public ComputationNode(@JsonProperty("type") NodeType type, @JsonProperty("valType") TypeInformation valType) {
		this.valType = valType;
		this.type = type;
	}

	public ComputationNode(VexOperation op) {
		this(op.tag);
	}

	public ComputationNode(VexOperationType opType) {
		this.oprType = opType;
		this.type = NodeType.calculate;
		this.valType = opType.getTypeInfo();

		TypeInformation valType = opType.getTypeInfo();
		int outSize = valType.outputType.numOfBit();

		Attribute attrs = opType.att();
		if (attrs == null) {
			logger.error("Unsupported operation {} opType. Consider implementing. ", opType);
			return;
		}
		if (attrs._to_size != null)
			if (outSize < attrs._to_size)
				logger.error(
						"VEX states `{}` should have {} bits as output, but its name indicates it should have larger {} bits as output",
						opType, outSize, attrs._to_size);
	}

	public ComputationNode(VexExpression exp, List<VexVariableType> tmpTypes) {
		this.expType = exp.tag;
		this.type = NodeType.calculate;
		this.valType = exp.getTypeInformation(tmpTypes);
	}

	public String varName;
	public String reqName;
	public int index;
	public int version;

	@JsonInclude
	public VexConstant constant;
	public Boolean isCntAddr = null;

	public TypeInformation valType;

	public List<String> parents = new ArrayList<>();
	public List<String> children = new ArrayList<>();
	public NodeType type = NodeType.var;

	@JsonInclude
	public VexOperationType oprType;
	@JsonInclude
	public VexExpressionType expType;

	public String ccall_oprName;

	// these information is available after the node is resolved (traversed)
	public int depth = -1;
	public int sHash = -1;
	public boolean isLatest = false;
	public HashSet<String> leaves = new HashSet<>();

	@JsonIgnore
	public boolean isConst() {
		return varName.startsWith(ComputationGraph.constantPrefix);
	}

	@JsonIgnore
	public boolean isAddr() {
		return isConst() && isCntAddr != null && isCntAddr == true;
	}

	@JsonIgnore
	public boolean isTmp() {
		return varName.startsWith(ComputationGraph.tempVarPrefix);
	}

	@JsonIgnore
	public boolean isMem() {
		return varName.startsWith(ComputationGraph.memPrefix);
	}

	@JsonIgnore
	public boolean isRegister() {
		return varName.startsWith(ComputationGraph.registerPrefix);
	}

	@JsonIgnore
	public boolean isIP(VexArchitectureType type) {
		return isRegister() && type.getGuestInfo().isProgramCounter(this);
	}

	@JsonIgnore
	public boolean isOperation() {
		return varName.startsWith(ComputationGraph.oprPrefix);
	}

	@JsonIgnore
	public String getOperationName() {
		String op = "";
		if (oprType != null)
			op = oprType.toString();
		else if (expType != null)
			op = expType.toString();
		if (ccall_oprName != null)
			op += ":" + ccall_oprName;
		return op;
	}

	@JsonIgnore
	public String desp(VexArchitectureType architectureType) {
		String desp = null;
		switch (type) {
		case var:
			desp = valType.outputType.shortString() + ":" + varName + (isAddr() ? "(addr)" : "");
			if (isIP(architectureType))
				desp = desp + "(ip)";
			if (isLatest)
				desp = desp + "(latest)";
			break;
		case calculate:
			desp = getOperationName() + " " + valType.toString();
			break;
		case mem:
			if (parents.size() == 1)
				desp = "lookup and get memory of type " + valType.outputType.shortString();
			if (parents.size() == 2 && parents.get(0) != null)
				desp = "lookup and assign memory of type" + valType.outputType.shortString();
			else
				desp = varName;
			break;
		case condition:
			desp = "if-then-else";
			break;
		default:
			break;
		}
		if (desp == null)
			desp = "ERROR:" + varName;
		return desp;
	}

	@JsonIgnore
	public List<ComputationNode> getParents(HashMap<String, ComputationNode> nodes) {
		return this.parents.stream().map(prt -> nodes.get(prt)).collect(Collectors.toList());
	}

	@JsonIgnore
	public List<ComputationNode> getParents(GenericGraph graph) {
		return this.getParents(graph.nodes);
	}

	@JsonIgnore
	public List<ComputationNode> getChildren(HashMap<String, ComputationNode> nodes) {
		return this.children.stream().map(chld -> nodes.get(chld)).collect(Collectors.toList());
	}

	@JsonIgnore
	public List<ComputationNode> getChildren(GenericGraph graph) {
		return this.getChildren(graph.nodes);
	}

	@Override
	public String toString() {
		return varName + ": parent(" + parents.toString() + ")children(" + children.toString() + ")";
	}

	public ComputationNode cal(VexOperationType type, ComputationGraph graph, ComputationNode... args) {
		ComputationNode calNode = new ComputationNode(type);
		ArrayList<ComputationNode> nodes = new ArrayList<>();
		nodes.add(this);
		nodes.addAll(Arrays.asList(args));
		return graph.addComputationNode(calNode, nodes);
	}

	public ComputationNode calWithVal(VexOperationType type, ComputationGraph graph, Integer... constants) {
		List<String> conts = Arrays.stream(constants).map(Integer::toHexString).collect(Collectors.toList());
		return calWithStr(type, graph, conts.toArray(new String[conts.size()]));
	}

	public ComputationNode calWithVal(VexOperationType type, ComputationGraph graph, Float... constants) {
		List<String> conts = Arrays.stream(constants).map(val -> Long.toHexString(Double.doubleToLongBits(val)))
				.collect(Collectors.toList());
		return calWithStr(type, graph, conts.toArray(new String[conts.size()]));
	}

	public ComputationNode calWithVal(VexOperationType type, ComputationGraph graph, Double... constants) {
		List<String> conts = Arrays.stream(constants).map(val -> Long.toHexString(Double.doubleToLongBits(val)))
				.collect(Collectors.toList());
		return calWithStr(type, graph, conts.toArray(new String[conts.size()]));
	}

	public ComputationNode calWithVal(VexOperationType type, ComputationGraph graph, Long... constants) {
		List<String> conts = Arrays.stream(constants).map(Long::toHexString).collect(Collectors.toList());
		return calWithStr(type, graph, conts.toArray(new String[conts.size()]));
	}

	public ComputationNode calWithStr(VexOperationType type, ComputationGraph graph, String... constants) {
		List<ComputationNode> conts = Arrays.stream(constants)
				.map(cont -> graph.getConstant(type.getTypeInfo().argType.get(1).numOfBit(), cont))
				.collect(Collectors.toList());
		return cal(type, graph, conts.toArray(new ComputationNode[conts.size()]));
	}

	@JsonIgnore
	public String sExpression(HashMap<String, ComputationNode> nodes) {

		String exprssion = "";
		switch (type) {
		case var:
			// direct assignment
			if (parents.size() == 1)
				exprssion = getParents(nodes).get(0).sExpression(nodes);
			else if (parents.size() == 0)
				return valType.outputType.shortString() + ":" + varName
						+ ((isCntAddr != null && isCntAddr == true) ? "(addr)" : "");
			;
			break;
		case mem:
			// arg[0] is address arg[1] is the value
			if (parents.size() == 1 && parents.get(0) != null)
				exprssion = valType.outputType.shortString() + ":[" + getParents(nodes).get(0).sExpression(nodes) + "]v"
						+ version;
			else if (parents.size() == 2)
				exprssion = getParents(nodes).get(1).sExpression(nodes);
			else
				exprssion = valType.outputType.shortString() + ":" + varName;
			break;
		case calculate:
			if (this.getOperationName().trim().length() < 1) {
				System.out.println("ERROR Operation name for " + varName);
			}
			exprssion = "(" + getOperationName() + ":" + valType.toString() + " " + StringResources.JOINER_TOKEN.join(
					getParents(nodes).stream().map(input -> input.sExpression(nodes)).collect(Collectors.toList()))
					+ ")";
			break;
		case condition:
			List<ComputationNode> ps = getParents(nodes);
			exprssion = "(if " + ps.get(0).sExpression(nodes) + " then " + ps.get(1).sExpression(nodes) + " else "
					+ ps.get(2).sExpression(nodes);
			break;
		default:
			exprssion = "(Error for " + varName + ")";
			break;
		}

		return exprssion;
	}

	@JsonIgnore
	public String traverseId(HashMap<String, ComputationNode> nodes, final int depth) {

		if (depth < 1)
			return varName;

		String exprssion = "";
		switch (type) {
		case var:
			// direct assignment
			if (parents.size() == 1)
				exprssion = getParents(nodes).get(0).traverseId(nodes, depth - 1);
			else if (parents.size() == 0)
				return varName;
			break;
		case mem:
			// arg[0] is address arg[1] is the value
			// if a memory variable is using another memory variable location as
			// address,
			// we can just indicate it using the memory id since we
			// version-controlled all memory symbol
			if (parents.size() == 1 && parents.get(0) != null)
				return varName;
			else if (parents.size() == 2)
				exprssion = getParents(nodes).get(1).traverseId(nodes, depth - 1);
			else
				exprssion = varName;
			break;
		case calculate:
			exprssion = oprType + StringResources.JOINER_TOKEN.join(getParents(nodes).stream()
					.map(input -> input.traverseId(nodes, depth - 1)).collect(Collectors.toList()));
			break;
		case condition:
			exprssion = "ITE " + StringResources.JOINER_TOKEN.join(getParents(nodes).stream()
					.map(input -> input.traverseId(nodes, depth - 1)).collect(Collectors.toList()));
			break;
		default:
			exprssion = StringResources.STR_EMPTY;
			break;
		}

		return exprssion;
	}

	@JsonIgnore
	public ComputationNode copyContentOnly() {
		ComputationNode newNode = new ComputationNode(type, valType);
		newNode.constant = constant;
		newNode.expType = expType;
		newNode.oprType = oprType;
		newNode.reqName = reqName;
		newNode.type = type;
		newNode.varName = varName;
		newNode.version = version;
		newNode.ccall_oprName = ccall_oprName;
		newNode.index = index;

		newNode.isLatest = this.isLatest;
		return newNode;
	}

	@JsonIgnore
	public ComputationNode resolve(ComputationGraph graph, boolean abstractMemRef) {
		return resolve(graph, new ComputationGraph(graph, false), false, abstractMemRef);
	}

	private static boolean nativeSimplification = true;

	@JsonIgnore
	public ComputationNode resolve(ComputationGraph graph, ComputationGraph newGraph, boolean isFirstNode,
			boolean abstractMemRef) {

		ComputationNode newNode = newGraph.nodes.get(varName);
		if (newNode != null)
			return newNode;

		this.isLatest = graph.isRegLatest(this);

		switch (type) {
		case var:
			if (parents.size() == 1) {
				if (!isFirstNode && !this.isLatest) {
					newNode = this.getParents(graph).get(0).resolve(graph, newGraph, false, abstractMemRef);
				} else {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					ComputationNode target = this.getParents(graph).get(0).resolve(graph, newGraph, false,
							abstractMemRef);
					newNode.parents.add(target.varName);
					target.children.add(newNode.varName);
					newNode.depth = target.depth + 1;
					newNode.sHash = target.sHash;
					newNode.leaves.addAll(target.leaves);
				}
			} else if (parents.size() == 0) {
				if (isConst()) {
					newNode = newGraph.getConstant(constant);
					newNode.depth = 0;
					if (newNode.isAddr())
						newNode.sHash = VAR_ADDR.hashCode();
					else
						newNode.sHash = Long.hashCode(constant.getVal());
					newNode.leaves.add(newNode.varName);
				} else {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					newNode.depth = 0;
					newNode.sHash = newNode.valType.outputType.hashCode();// VAR_IDENTIFIER.hashCode();
					newNode.leaves.add(newNode.varName);
				}
			} else {
				logger.error("A var node should have no more than one parent: {}: {}", varName, toString());
			}
			break;
		case mem:
			if (!abstractMemRef) {

				if (parents.size() == 1) {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					ComputationNode addr = getParents(graph).get(0).resolve(graph, newGraph, false, abstractMemRef);
					newNode.parents.add(addr.varName);
					addr.children.add(newNode.varName);
					newNode.depth = addr.depth + 1;
					newNode.sHash = addr.sHash;
					newNode.leaves.addAll(addr.leaves);
				} else if (parents.size() == 2 && !isFirstNode) {
					newNode = getParents(graph).get(1).resolve(graph, newGraph, false, abstractMemRef);
				} else if (parents.size() == 2 && isFirstNode) {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					ComputationNode addr = getParents(graph).get(0).resolve(graph, newGraph, false, abstractMemRef);
					ComputationNode data = getParents(graph).get(1).resolve(graph, newGraph, false, abstractMemRef);
					newNode.parents.add(addr.varName);
					newNode.parents.add(data.varName);
					addr.children.add(newNode.varName);
					data.children.add(newNode.varName);
					newNode.depth = data.depth + 1;
					HashCodeBuilder builder = new HashCodeBuilder();
					builder.append(data.sHash);
					builder.append(addr.sHash);
					newNode.sHash = builder.build();
					newNode.leaves.addAll(data.leaves);
					newNode.leaves.addAll(addr.leaves);
				} else
					logger.error(
							"memory can only has one address to look up. But {} has no or more than one address {}",
							varName, parents);
			} else {
				if (parents.size() == 2 && !isFirstNode) {
					newNode = getParents(graph).get(1).resolve(graph, newGraph, false, abstractMemRef);
				} else if (parents.size() == 2 && isFirstNode) {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					ComputationNode data = getParents(graph).get(1).resolve(graph, newGraph, false, abstractMemRef);
					newNode.parents.add(null);
					newNode.parents.add(data.varName);
					data.children.add(newNode.varName);
					newNode.depth = data.depth + 1;
					newNode.sHash = data.sHash;
					newNode.leaves.addAll(data.leaves);
				} else {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					newNode.depth = 0;
					newNode.sHash = newNode.valType.outputType.hashCode(); // VAR_IDENTIFIER.hashCode();
					newNode.leaves.add(newNode.varName);
				}
			}
			break;
		case calculate: {
			List<ComputationNode> args = this.getParents(graph).stream()
					.map(arg -> arg.resolve(graph, newGraph, false, abstractMemRef)).collect(Collectors.toList());

			long numNonConstant = args.stream().filter(arg -> !arg.isConst()).count();
			// if input are all constants, we calculate and create a new
			// constant node

			if (this.getOperationName().trim().length() < 1) {
				System.out.println("ERROR");
			}

			if (this.oprType != null //
					&& this.oprType.att() != null //
					&& this.oprType.att()._generic_name != null //
					&& !this.oprType.att().isV() //
					&& !this.oprType.att().isF() //
					&& !this.oprType.att().isV() //
					&& VexConstantSimplifier.map.containsKey(this.oprType.att()._generic_name) //
					&& nativeSimplification) {

				if (numNonConstant == 0) {
					VexOperationInJava func = VexConstantSimplifier.map.get(this.oprType.att()._generic_name);
					List<String> constants = args.stream().map(nd -> nd.constant.value).collect(Collectors.toList());
					String val = func.calculate(this.oprType.att(), constants.toArray(new String[constants.size()]));
					ComputationNode newConst = newGraph.getConstant(valType.outputType.numOfBit(), val);
					newConst.depth = 0;
					newNode = newConst;
					newNode.sHash = Long.hashCode(newConst.constant.getVal());
					newNode.leaves.add(newNode.varName);
				}
			}

			// if is non of the above situation
			if (newNode == null) {

				newNode = this.copyContentOnly();
				newGraph.nodes.put(newNode.varName, newNode);

				for (ComputationNode arg : args) {
					arg.children.add(newNode.varName);
					newNode.parents.add(arg.varName);
				}

				int mindepth = args.stream().mapToInt(arg -> arg.depth).filter(dep -> dep != -1).min().getAsInt();
				newNode.depth = mindepth + 1;

				if (oprType != null) {
					// Attribute att = oprType.att();
					// if (att.isConvert() && !att.isF() && args.size() == 1) {
					// newNode.sHash = args.get(0).sHash;
					// } else {
					HashCodeBuilder hasher = new HashCodeBuilder();
					hasher.append(oprType);
					if (oprType.att() != null && oprType.att().isOrderSensitive())
						args.stream().mapToInt(nd -> nd.sHash).forEach(hsc -> hasher.append(hsc));
					else
						args.stream().mapToInt(nd -> nd.sHash).sorted().forEach(hsc -> hasher.append(hsc));
					newNode.sHash = hasher.build();
					// }
				} else if (ccall_oprName != null) {
					// the order of params matters for ccall (assumed. in
					// most case is truth. otherwise we
					// need to concretize opr and cond.)
					HashCodeBuilder hasher = new HashCodeBuilder();
					hasher.append(ccall_oprName);
					args.stream().mapToInt(nd -> nd.sHash).sorted().forEach(hsc -> hasher.append(hsc));
					newNode.sHash = hasher.build();
				}

				newNode.leaves.addAll(args.stream().flatMap(arg -> arg.leaves.stream()).collect(Collectors.toList()));
				if (this.ccall_oprName != null && this.ccall_oprName.equals("x86g_use_seg_selector"))
					System.out.println(this.sExpression(graph.nodes));
			}
			break;
		}
		case condition: {

			List<ComputationNode> ptrs = this.getParents(graph);
			if (ptrs.size() != 3) {
				logger.error("ITE condition must have at least ");
			} else {
				ComputationNode cond = ptrs.get(0).resolve(graph, newGraph, false, abstractMemRef);
				if (cond.isConst() && nativeSimplification) {
					// if the first argument (condition) is a constant:
					// we can directly check if it is zero now:
					// It returns iftrue (arg[1]) if cond is nonzero, iffalse
					// (arg[2]) otherwise.

					long condVal = cond.constant.getVal();
					if (condVal != 0) {
						newNode = ptrs.get(1).resolve(graph, newGraph, false, abstractMemRef);
					} else {
						newNode = ptrs.get(2).resolve(graph, newGraph, false, abstractMemRef);
					}
				} else {
					newNode = this.copyContentOnly();
					newGraph.nodes.put(newNode.varName, newNode);
					ComputationNode iftrue = ptrs.get(1).resolve(graph, newGraph, false, abstractMemRef);
					ComputationNode iffalse = ptrs.get(2).resolve(graph, newGraph, false, abstractMemRef);

					for (ComputationNode arg : Arrays.asList(cond, iftrue, iffalse)) {
						arg.children.add(newNode.varName);
						newNode.parents.add(arg.varName);
					}
					int mindepth = Arrays.asList(iftrue, iffalse).stream().mapToInt(arg -> arg.depth)
							.filter(dep -> dep != -1).min().getAsInt();
					newNode.depth = mindepth + 1;
					HashCodeBuilder builder = new HashCodeBuilder();
					builder.append(VAR_ITE);
					builder.append(cond.sHash);
					builder.append(iftrue.sHash);
					builder.append(iffalse.sHash);
					newNode.sHash = builder.build();

					newNode.leaves.addAll(cond.leaves);
					newNode.leaves.addAll(iftrue.leaves);
					newNode.leaves.addAll(iffalse.leaves);

				}
			}

			break;
		}
		default:
			logger.error("Error for {}; returning null.", varName);
			break;
		}
		return newNode;
	}

	@JsonIgnore
	public <T> T transform(GenericGraph graph, Function<ComputationNode, T> func) {
		return func.apply(this);
	}

}