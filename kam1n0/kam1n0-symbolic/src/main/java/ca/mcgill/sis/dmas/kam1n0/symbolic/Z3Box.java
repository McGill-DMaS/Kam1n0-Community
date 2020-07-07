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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecNum;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Model;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.Assignment;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunResult;
import ca.mcgill.sis.dmas.kam1n0.vex.DirtyCalls;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexConstant;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.Attribute;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.RoundingMode;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

public class Z3Box {

	private String prefix;

	@Deprecated
	public Long concretizeValue(SimNode symbol) {
		return concretizeValue(symbol, false);
	}

	public SimNode getDefaultValue() {
		return SimNode.val(ctx, 0x0, architecture.defaultTypte().numOfBit());
	}

	@Deprecated
	public Long concretizeValue(SimNode symbol, boolean anyIfNotFind) {
		Solver solver = ctx.mkSolver();
		if (solver.check() == Status.SATISFIABLE) {
			Model model = solver.getModel();
			Expr exp = model.eval(symbol.e, anyIfNotFind);
			long result = ((BitVecNum) exp).getLong();
			return (long) ((int) result);
		} else {
			logger.error("Failed to concretize:" + symbol);
			return null;
		}
	}

	@SafeVarargs
	public final SimNode symSwitch(SimNode inputVal, SimNode defaultVal,
			EntryPair<Integer, Supplier<SimNode>>... conditions) {
		return this.condition(
				Arrays.stream(conditions).collect(Collectors.toMap(ent -> ent.key, ent -> ent.value.get())), inputVal,
				defaultVal);
	}

	@SafeVarargs
	public final SimNode symSwitchMultiKey(SimNode inputVal, SimNode defaultVal,
			EntryPair<Integer[], Supplier<SimNode>>... conditions) {
		return this.condition(Arrays.stream(conditions)
				.flatMap(ent -> Arrays.stream(ent.key).map(key -> new EntryPair<>(key, ent.value)))
				.collect(Collectors.toMap(ent -> ent.key, ent -> ent.value.get())), inputVal, defaultVal);
	}

	public SimNode condition(Map<Integer, SimNode> conditionMap, SimNode input, SimNode defaultValue) {
		ArrayList<HashMap.Entry<Integer, SimNode>> conds = new ArrayList<>(conditionMap.entrySet());
		assert conds.size() > 0;
		SimNode result = this.createCondition(input.cmpeq(conds.get(0).getKey()), conds.get(0).getValue(),
				defaultValue);
		for (int i = 1; i < conds.size(); ++i) {
			result = this.createCondition(input.cmpeq(conds.get(i).getKey()), conds.get(i).getValue(), result);
		}
		return result;
	}

	static BitVecExpr ABS(Context ctx, BitVecExpr val) {
		return (BitVecExpr) ctx.mkITE(ctx.mkBVSGE(val, ctx.mkBV(0x0, val.getSortSize())), val, ctx.mkBVNeg(val));
	}

	private static Logger logger = LoggerFactory.getLogger(Z3Box.class);

	public Z3Box(Context ctx, VexArchitectureType architecture, String prefix) {
		this.ctx = ctx;
		this.architecture = architecture;
		this.prefix = prefix;
	}

	// public Z3Box(int defaultBitSize) {
	// HashMap<String, String> cfg = new HashMap<String, String>();
	// cfg.put("model", "true");
	// this.ctx = new Context(cfg);
	// this.defaultSize = defaultBitSize;
	//
	// }

	Context ctx;
	VexArchitectureType architecture;

	public SimNode createVar(String varName, VexVariableType type) {
		SimNode exp = new SimNode(ctx, prefix + varName, type);
		return exp;
	}

	public SimNode createConstant(String constantName, VexConstant constant) {
		VexVariableType type = constant.type.toVariableType();
		SimNode exp = new SimNode(ctx, constant.getVal(), type);
		return exp;
	}

	public SimNode createConstant(String constantName, long value, int bits) {
		VexVariableType type = VexVariableType.valueOf("Ity_I" + bits);
		SimNode exp = new SimNode(ctx, value, type);
		return exp;
	}

	public SimNode ite(SimNode ifExpr, SimNode thenDo, SimNode elseDo) {
		return createCondition(ifExpr, thenDo, elseDo);
	}

	public SimNode createCondition(SimNode ifExpr, SimNode thenDo, SimNode elseDo) {
		thenDo = thenDo.mkCompatible(elseDo, false);
		elseDo = elseDo.mkCompatible(thenDo, false);
		BoolExpr ifExprCmpZero = ctx.mkNot(ctx.mkEq(ifExpr.e, ctx.mkBV(0x0, ifExpr.size())));
		SimNode exp = new SimNode(ctx, (BitVecExpr) ctx.mkITE(ifExprCmpZero, thenDo.e, elseDo.e), thenDo.t);
		return exp;
	}

	public static SimNode convert(Context ctx, SimNode val, VexVariableType toType, boolean signed, String fromSide,
			RoundingMode mode, SimNode smode) {

		VexVariableType fromType = val.t;

		if (fromType.isD() || toType.isD()) {
			logger.error("D types conversion are not supported. from {} to {}", fromType, toType);
			return null;
		}
		if (val.size() > val.t.numOfBit()) {
			val = val.extract(val.t.numOfBit() - 1, 0);
		}
		if (val.size() < val.t.numOfBit()) {
			logger.error("The input simnode of size {} is bigger than what is expected of its type {}.", val.size(),
					val.t);
		}

		// if (fromType.isV() || toType.isV()) {
		// if (fromType.isV() && toType.isV()) {
		// if (fromType.numOfBit() != toType.numOfBit()) {
		// logger.error(
		// "Both of the args for conversion of vector type need to have equal
		// size. but {} and {} provided. Converted to the bigger size.",
		// fromType, toType);
		// if (toType.numOfBit() > fromType.numOfBit()) {
		// SimNode converted = null;
		// if (signed) {
		// converted = val.signExtend(toType.numOfBit());
		// } else {
		// converted = val.zeroExtend(toType.numOfBit());
		// }
		// return converted;
		// }
		// }
		// } else {
		// logger.error("Both of the args for conversion of vector type need to
		// be v. but {} and {} provided.",
		// fromType, toType);
		// return null;
		// }
		// }

		// vector type conversion is treated as signed/unsigned bv conversion.
		if (!fromType.isF() && !toType.isF()) {
			SimNode converted = null;
			if (toType.numOfBit() > fromType.numOfBit()) {
				// deal with signed / unsigned type I extend:
				if (signed) {
					converted = val.signExtend(toType.numOfBit());
				} else {
					converted = val.zeroExtend(toType.numOfBit());
				}
			} else {
				// deal with type I extract:
				int start = 0, end = 0;
				if (fromSide != null && fromSide.equalsIgnoreCase("HI")) {
					start = val.size() - 1;
					end = val.size() / 2;
				} else if (fromSide != null && fromSide.equalsIgnoreCase("LO")) {
					start = val.size() / 2 - 1;
					end = 0;
				} else {
					start = toType.numOfBit() - 1;
					end = 0;
				}
				converted = val.extract(start, end);
			}
			return converted;
		} else if (!fromType.isF() && toType.isF()) {
			if (smode != null) {
				SimNode converted = val.toFloat(toType.numOfBit(), signed, smode);
				return converted;
			} else {
				SimNode converted = val.toFloat(toType.numOfBit(), signed, mode);
				return converted;
			}
		} else if (fromType.isF() && !toType.isF()) {
			if (smode != null) {
				SimNode converted = val.toInt(toType.numOfBit(), signed, smode);
				return converted;
			} else {
				SimNode converted = val.toInt(toType.numOfBit(), signed, mode);
				return converted;
			}
		} else if (fromType.isF() && toType.isF()) {
			if (smode != null) {
				SimNode converted = val.toFloat(toType.numOfBit(), signed, smode);
				return converted;
			} else {
				SimNode converted = val.toFloat(toType.numOfBit(), signed, mode);
				return converted;
			}
		}

		logger.error("Unsupport conversion from {} to {}", fromType, toType);
		return null;
	}

	public SimNode createOperation(VexOperationType opr, List<SimNode> args) {

		Attribute att = opr.att();
		TypeInformation typeInfo = opr.getTypeInfo();
		VexVariableType outputType = typeInfo.outputType;

		if (att.isD()) {
			logger.error("D {} types are not supported", att);
			return null;
		}

		if (typeInfo.argType.size() != args.size()) {
			logger.error("The size of tpye signature of opr {} does not match input args {}", opr, args);
			return null;
		}

		// check type for the argument
		// (convert them into the required input type if necessary)
		List<SimNode> chkArgs = new ArrayList<>();
		for (int i = 0; i < args.size(); i++) {
			SimNode arg = args.get(i);
			VexVariableType requiredType = typeInfo.argType.get(i);
			if (arg.t == null) {
				System.out.println("");
			}
			if (arg.t.equals(requiredType)) {
				chkArgs.add(args.get(i));
			} else {
				// logger.info("converting arg {} to {} for {}", arg.t,
				// requiredType, opr);
				SimNode val = convert(ctx, arg, requiredType, att.isSigned(), att._from_side, att.getRM(), null);
				if (val == null)
					return null;
				else
					chkArgs.add(val);
			}
		}
		SimNode node = null;
		if (!att.isV()) {
			// convert
			if (att.isConvert()) {
				node = generalConverionOperations(att, chkArgs, outputType);
				if (node != null)
					return node;
			}
			// general one (signed/unsigned I type)
			if (!att.isF()) {
				node = generalBVOperations(att, chkArgs, outputType);
				if (node != null)
					return node;
			}
			// float
			if (att.isF()) {
				if (!att.isV0())
					node = generalFloatOperation(att, chkArgs, outputType);
				if (node != null)
					return node;
			}
		} else {
			// float with v0 operation
			if (att.isF() && att.isV0()) {
				// only one operation is conducted.
				int vsize = att.getVSize();
				if (vsize != -1) {
					SimNode arg0 = chkArgs.get(0);
					VexVariableType localInType = att.getFromType(this.architecture);
					VexVariableType localOutType = att.getVType(this.architecture);
					List<SimNode> extracted = new ArrayList<>();

					for (int j = 0; j < chkArgs.size(); j++) {
						if (j == 0 && typeInfo.hasRM) {
							// if this opr contains a rounding mode
							// parameter at the first place.
							// we ignore the case (32, 8) -> 32
							// since this generally not applicable for floating
							// point operation.
							// usually it is for bv operation like shift.
							extracted.add(chkArgs.get(j));
						} else {
							SimNode localChkArg = chkArgs.get(j).extract(vsize - 1, 0);
							if (localInType.isF()) {
								localChkArg = localChkArg.reinerpretAsFloat();
							}
							extracted.add(localChkArg);
						}
					}

					node = generalFloatOperation(att, extracted, VexVariableType.getFltType(localOutType.numOfBit()));
					node = arg0.extract(arg0.size() - 1, vsize).concate(node);
					assert node.size() == arg0.size();
				}
				if (node != null)
					return node;
			}

			// prepare vectors (non-v0)
			if (!att.isV0()) {
				int vsize = att._from_size == null
						? (att.getVSize() == -1 ? architecture.defaultTypte().numOfBit() : att.getVSize())
						: att._from_size;
				int vcount = att.getVCount();

				node = generalVManipulationOperation(att, chkArgs, vsize, vcount);
				if (node != null)
					return node;

				if (vsize * vcount == chkArgs.get(0).size()
						&& att.getVSize() * att.getVCount() == outputType.numOfBit()) {

					VexVariableType localInType = att.getFromType(this.architecture);
					VexVariableType localOutType = att.getVType(this.architecture);

					if (vsize != -1 && vcount != -1) {
						node = null;
						for (int i = vcount - 1; i >= 0; --i) {
							int hi = (i + 1) * vsize - 1;
							int lo = i * vsize;

							SimNode r1 = null;

							List<SimNode> extracted = new ArrayList<>();

							// some of the arguments shouldn't be splited into
							// elements. such as: Iop_ShlN64x2
							// or other floating point algorithmic operation
							// that has
							// a rounding mode I32/I8

							for (int j = 0; j < chkArgs.size(); j++) {
								VexVariableType localArgType = typeInfo.argType.get(j);
								if (localArgType.numOfBit() != vcount * vsize || (j == 0 && typeInfo.hasRM)) {
									// if the bv does not fit the vector
									// definition of this opr.
									// or this opr contains a rounding mode
									// parameter at the first place.
									extracted.add(chkArgs.get(j));
								} else {
									// else we do the slicing
									SimNode localChkArg = chkArgs.get(j).extract(hi, lo);
									if (localInType.isF()) {
										localChkArg = localChkArg.reinerpretAsFloat();
									}
									extracted.add(localChkArg);
								}
							}

							if (att.isConvert()) {
								r1 = generalConverionOperations(att, extracted, localOutType);
							} else if (!att.isF()) {
								r1 = generalBVOperations(att, extracted, localOutType);
							} else if (att.isF()) {
								r1 = generalFloatOperation(att, extracted, localOutType);
							}

							if (r1 == null)
								break;
							if (node == null)
								node = r1;
							else
								node = node.concate(r1);
						}
						if (node != null)
							return node;
					}
				}
			}
		}

		// logger.error("Unsupported operation: " + opr + " : " + att._generic_name);
		return null;
	}

	public SimNode generalVManipulationOperation(Attribute att, List<SimNode> chkArgs, int vsize, int vcount) {

		switch (att._generic_name) {
		case "InterleaveH":
		case "InterleaveHI":
		case "InterleaveLO":
		case "InterleaveOddLanes":
		case "InterleaveEvenLanes": {
			String mode = att._generic_name.replace("Interleave", "");
			assert chkArgs.size() == 2;
			switch (mode) {
			case "H":
			case "HI": {
				SimNode arg0 = chkArgs.get(0);
				SimNode arg1 = chkArgs.get(1);

				// higher half
				SimNode ms = arg0.extract(arg0.size() - 1, arg0.size() / 2);
				SimNode ls = arg1.extract(arg1.size() - 1, arg1.size() / 2);
				return ms.concate(ls);
			}
			case "LO": {
				SimNode arg0 = chkArgs.get(0);
				SimNode arg1 = chkArgs.get(1);

				// higher half
				SimNode ms = arg0.extract(arg0.size() / 2 - 1, 0);
				SimNode ls = arg1.extract(arg0.size() / 2 - 1, 0);
				return ms.concate(ls);
			}
			case "OddLanes": {
				SimNode result = null;
				SimNode arg0 = chkArgs.get(0);
				SimNode arg1 = chkArgs.get(1);

				for (int i = vcount - 1; i >= 0; --i) {
					int hi = (i + 1) * vsize - 1;
					int lo = i * vsize;
					if (i % 2 == 0) {
						SimNode element = arg0.extract(hi, lo);
						if (result == null)
							result = element;
						else
							result = result.concate(element);
					}
				}

				for (int i = vcount - 1; i >= 0; --i) {
					int hi = (i + 1) * vsize - 1;
					int lo = i * vsize;
					if (i % 2 == 0) {
						SimNode element = arg1.extract(hi, lo);
						if (result == null)
							result = element;
						else
							result = result.concate(element);
					}
				}

				return result;
			}
			case "EvenLanes": {
				SimNode result = null;
				SimNode arg0 = chkArgs.get(0);
				SimNode arg1 = chkArgs.get(1);

				for (int i = vcount - 1; i >= 0; --i) {
					int hi = (i + 1) * vsize - 1;
					int lo = i * vsize;
					if (i % 2 == 1) {
						SimNode element = arg0.extract(hi, lo);
						if (result == null)
							result = element;
						else
							result = result.concate(element);
					}
				}

				for (int i = vcount - 1; i >= 0; --i) {
					int hi = (i + 1) * vsize - 1;
					int lo = i * vsize;
					if (i % 2 == 1) {
						SimNode element = arg1.extract(hi, lo);
						if (result == null)
							result = element;
						else
							result = result.concate(element);
					}
				}

				return result;
			}
			default:
				logger.info("Unsupported interleave operation mode {} of {}. Consider implementing.", mode,
						att._generic_name);
				break;
			}
			return null;
		}
		case "QNarrowBin":
		case "NarrowBin": {
			VexVariableType localOutType = att.getVType(this.architecture);
			SimNode arg0 = chkArgs.get(0);
			SimNode arg1 = chkArgs.get(1);
			SimNode node = null;
			vcount = vcount / 2;
			for (int i = vcount - 1; i >= 0; --i) {
				int hi = (i + 1) * vsize - 1;
				int lo = i * vsize;

				SimNode r1 = arg0.extract(hi, lo);
				r1 = r1.to(localOutType, att.isVSigned());
				if (node == null)
					node = r1;
				else
					node = node.concate(r1);
			}
			for (int i = vcount - 1; i >= 0; --i) {
				int hi = (i + 1) * vsize - 1;
				int lo = i * vsize;

				SimNode r1 = arg1.extract(hi, lo);
				r1 = r1.to(localOutType, att.isVSigned());
				node = node.concate(r1);
			}
			return node;

		}
		}
		return null;
	}

	public SimNode generalConverionOperations(Attribute att, List<SimNode> chkArgs, VexVariableType outputType) {
		if (att.isConvertOnly()) {
			if (att._from_side != null && att._from_side.equals("HL")) {
				return new SimNode(ctx, ctx.mkConcat(chkArgs.get(0).e, chkArgs.get(1).e), outputType);
			} else {

				if (chkArgs.size() > 2) {
					logger.error("Conversion finds more than two arguments for " + att.toString());
				}

				if (chkArgs.size() == 2) {
					SimNode rm = chkArgs.get(0);
					SimNode val = chkArgs.get(1);
					if (!rm.isFloat() && val != null) {
						return convert(ctx, val, outputType, att.isSigned(), att._from_side, null, rm);
					} else {
						logger.error(
								"Conversion suspects a float point conversion with two arguments. but the type does not match (roundmode,float_val). "
										+ att.toString());
						return null;
					}
				} else
					return convert(ctx, chkArgs.get(0), outputType, att.isSigned(), att._from_side, att.getRM(), null);
			}
		} else if (att._generic_name.equals("DivMod")) {
			// e.g. 64 bit -> 64 bit
			SimNode arg0 = chkArgs.get(0);
			// e.g. 32 bit -> 64 bit
			SimNode arg1 = convert(ctx, chkArgs.get(1), chkArgs.get(0).t, att.isSigned(), null, null, null);
			if (att.isSigned()) {
				BitVecExpr quotient = ctx.mkBVSDiv(arg0.e, arg1.e);
				BitVecExpr remainder = ctx.mkBVSMod(arg0.e, arg1.e);
				BitVecExpr concated = ctx.mkConcat(ctx.mkExtract(outputType.numOfBit() / 2 - 1, 0, remainder),
						ctx.mkExtract(outputType.numOfBit() / 2 - 1, 0, quotient));
				return new SimNode(ctx, concated, outputType);
			} else {
				BitVecExpr quotient = ctx.mkBVUDiv(arg0.e, arg1.e);
				BitVecExpr remainder = ctx.mkBVURem(arg0.e, arg1.e);
				BitVecExpr concated = ctx.mkConcat(ctx.mkExtract(outputType.numOfBit() / 2 - 1, 0, remainder),
						ctx.mkExtract(outputType.numOfBit() / 2 - 1, 0, quotient));
				return new SimNode(ctx, concated, outputType);
			}
		} else {
			// all other conversion cases: round, widen, narrow, trunc
			// etc.

			if (att.isConvertAs()) {
				// reinterpret as a different type.
				return chkArgs.get(0).reinerpret(att.getToType(architecture));
			}

			if (chkArgs.size() == 2) {
				SimNode rm = chkArgs.get(0);
				SimNode val = chkArgs.get(1);
				if (!rm.isFloat() && val != null) {
					return convert(ctx, val, outputType, att.isSigned(), att._from_side, null, rm);
				} else {
					logger.error(
							"Conversion suspects a float point conversion with two arguments. but the type does not match (roundmode,float_val). "
									+ att.toString());
					return convert(ctx, chkArgs.get(0), outputType, att.isSigned(), att._from_side, att.getRM(), null);
				}
			} else
				return convert(ctx, chkArgs.get(0), outputType, att.isSigned(), att._from_side, att.getRM(), null);
		}
	}

	public SimNode generalBVOperations(Attribute att, List<SimNode> chkArgs, VexVariableType outputType) {
		SimNode node = generalBitOperations(att, chkArgs, outputType);
		if (node != null)
			return node;

		node = generalAlgOperation(att, chkArgs, outputType);
		if (node != null)
			return node;

		node = generalCmpOperations(att, chkArgs, outputType);
		if (node != null)
			return node;
		return null;
	}

	public SimNode generalBitOperations(Attribute att, List<SimNode> chkArgs, VexVariableType outputType) {
		if (att._generic_name.equals("Xor")) {
			return chkArgs.get(0).xor(chkArgs.get(1));
		} else if (att._generic_name.equals("Or")) {
			return chkArgs.get(0).or(chkArgs.get(1));
		} else if (att._generic_name.equals("And")) {
			return chkArgs.get(0).and(chkArgs.get(1));
		} else if (att._generic_name.equals("Not")) {
			return chkArgs.get(0).not();
		} else if (att._generic_name.equals("Clz")) {
			return chkArgs.get(0).clz();
		} else if (att._generic_name.equals("Ctz")) {
			return chkArgs.get(0).ctz();
		} else if (att._generic_name.equals("Set")) {
			return chkArgs.get(0).setLo(chkArgs.get(1));
		}
		return null;
	}

	public SimNode generalCmpOperations(Attribute att, List<SimNode> chkArgs, VexVariableType outputType) {
		if (att._generic_name.equals("CmpEQ") || att._generic_name.equals("CasCmpEQ")) {
			return chkArgs.get(0).cmpeq(chkArgs.get(1));
		} else if (att._generic_name.equals("CmpNE") || att._generic_name.equals("CasCmpNE")
				|| att._generic_name.equals("ExpCmpNE")) {
			return chkArgs.get(0).cmpne(chkArgs.get(1));
		} else if (att._generic_name.equals("CmpNEZ")) {
			return chkArgs.get(0).cmpnez();
		} else if (att._generic_name.equals("CmpGT") || att._generic_name.equals("CasCmpGT")) {
			return chkArgs.get(0).cmpgt(chkArgs.get(1), att.isSigned());
		} else if (att._generic_name.equals("CmpGE") || att._generic_name.equals("CasCmpGE")) {
			return chkArgs.get(0).cmpge(chkArgs.get(1), att.isSigned());
		} else if (att._generic_name.equals("CmpLT") || att._generic_name.equals("CasCmpLT")) {
			return chkArgs.get(0).cmplt(chkArgs.get(1), att.isSigned());
		} else if (att._generic_name.equals("CmpLE") || att._generic_name.equals("CasCmpLE")) {
			return chkArgs.get(0).cmple(chkArgs.get(1), att.isSigned());
		} else if (att._generic_name.equals("CmpORD")) {
			return chkArgs.get(0).cmpord(chkArgs.get(1), att.isSigned());
		}

		return null;
	}

	public SimNode generalAlgOperation(Attribute att, List<SimNode> chkArgs, VexVariableType outputType) {

		switch (att._generic_name) {
		case "Add":
		case "QAdd":
			return chkArgs.get(0).add(chkArgs.get(1));
		case "Sub":
			return chkArgs.get(0).sub(chkArgs.get(1));
		case "Mul":
			return chkArgs.get(0).mul(chkArgs.get(1));
		case "Div":
			return chkArgs.get(0).div(chkArgs.get(1), att.isSigned());
		case "Abs":
			return chkArgs.get(0).abs();
		case "ShlN":
		case "Shl":
			return chkArgs.get(0).shl(chkArgs.get(1));
		case "ShrN":
		case "Shr":
			return chkArgs.get(0).shr(chkArgs.get(1));
		case "SarN":
		case "Sar":
			return chkArgs.get(0).sar(chkArgs.get(1));
		case "Mull":
			return chkArgs.get(0).mull(chkArgs.get(1), outputType, att.isSigned());
		}

		return null;
	}

	public SimNode generalFloatOperation(Attribute att, List<SimNode> chkArgs, VexVariableType outputType) {
		SimNode arg0 = null;
		SimNode arg1 = null;
		SimNode arg2 = null;
		RoundingMode rmc = null;
		SimNode rm = null;
		int offset = 0;

		if (!chkArgs.get(0).isFloat()) {
			rm = chkArgs.get(0);
			offset = 1;
		} else
			rmc = att.getRM();

		arg0 = chkArgs.get(offset);
		offset++;
		if (offset < chkArgs.size())
			arg1 = chkArgs.get(offset);
		offset++;
		if (offset < chkArgs.size())
			arg2 = chkArgs.get(offset);

		assert rm == null || !rm.isFloat();
		assert rmc != null || rm != null;
		assert arg0 != null && arg0.isFloat();
		assert arg1 == null || arg1.isFloat();
		assert arg2 == null || arg2.isFloat();

		switch (att._generic_name) {
		case "Cmp":
			return arg0.fpCmp(arg1);
		case "CmpEQ":
		case "EQ":
			return arg0.fpEq(arg1);
		case "CmpNE":
		case "CmpUN":
		case "NE":
			return arg0.fpNeq(arg1);
		case "CmpGT":
		case "GT":
			return arg0.fpGt(arg1);
		case "CmpGEQ":
		case "CmpGE":
		case "GEQ":
			return arg0.fpGe(arg1);
		case "CmpLT":
		case "LT":
			return arg0.fpLt(arg1);
		case "CmpLEQ":
		case "CmpLE":
		case "LEQ":
			return arg0.fpLe(arg1);
		case "Abs":
			return arg0.fpAbs();
		case "Neg":
			return arg0.fpNeg();
		case "Min":
			return arg0.fpMin(arg1);
		case "Max":
			return arg0.fpMax(arg1);
		case "Sub":
			if (rm != null)
				return arg0.fpSub(arg1, rm);
			else
				return arg0.fpSub(arg1, rmc);
		case "Add":
			if (rm != null)
				return arg0.fpAdd(arg1, rm);
			else
				return arg0.fpAdd(arg1, rmc);
		case "Mul":
			if (rm != null)
				return arg0.fpMul(arg1, rm);
			else
				return arg0.fpMul(arg1, rmc);
		case "Div":
			if (rm != null)
				return arg0.fpDiv(arg1, rm);
			else
				return arg0.fpDiv(arg1, rmc);
		case "Sqrt":
			if (rm != null)
				return arg0.fpSqrt(rm);
			else
				return arg0.fpSqrt(rmc);
		case "MAdd":
			if (rm != null)
				return arg0.fpMAdd(arg1, arg2, rm);
			else
				return arg0.fpMAdd(arg1, arg2, rmc);
		case "MSub":
			if (rm != null)
				return arg0.fpMSub(arg1, arg2, rm);
			else
				return arg0.fpMSub(arg1, arg2, rmc);

		}

		return null;
	}

	public SimNode createCCall(String varName, String ccallName, TypeInformation types, List<SimNode> args) {
		SimNode node = null;
		try {
			node = SymbolicCCalls.call(ccallName, this, types, args);
		} catch (Exception e) {
			logger.error("ccall " + ccallName + " failed.", e);
		}
		return node;
	}

}
