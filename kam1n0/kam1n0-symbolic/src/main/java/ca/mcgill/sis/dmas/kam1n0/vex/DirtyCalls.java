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
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph.NodeType;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.SimNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.Z3Box;
import ca.mcgill.sis.dmas.kam1n0.symbolic.SymbolicCCalls.CCallFunction;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExConst;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmDirty;

public class DirtyCalls {

	private static Logger logger = LoggerFactory.getLogger(DirtyCalls.class);

	public static interface DCallFunction {
		public void calculate(StmDirty stmDirty, ComputationGraph graph);
	}

	private static HashMap<String, DCallFunction> callees = new HashMap<>();

	public static boolean implemented(String name) {
		return callees.containsKey(name);
	}

	static {
		callees.put("mips_dirtyhelper_calculate_FCSR_fp32", DirtyCalls::mips_dirtyhelper_calculate_FCSR_fp32);
		callees.put("x86g_dirtyhelper_CPUID_sse2", DirtyCalls::x86g_dirtyhelper_CPUID_sse0);
		callees.put("x86g_dirtyhelper_CPUID_sse3", DirtyCalls::x86g_dirtyhelper_CPUID_sse0);
		callees.put("x86g_dirtyhelper_CPUID_sse0", DirtyCalls::x86g_dirtyhelper_CPUID_sse0);
		callees.put("x86g_dirtyhelper_IN", DirtyCalls::x86g_dirtyhelper_IN);
		callees.put("x86g_dirtyhelper_OUT", DirtyCalls::x86g_dirtyhelper_OUT);
		callees.put("x86g_dirtyhelper_loadF80le", DirtyCalls::x86g_dirtyhelper_loadF80le);
		callees.put("x86g_dirtyhelper_storeF80le", DirtyCalls::x86g_dirtyhelper_storeF80le);
	}

	public static void call(StmDirty stmDirty, ComputationGraph graph) {
		if (stmDirty.cee != null && implemented(stmDirty.cee.name)) {
			DCallFunction callee = callees.get(stmDirty.cee.name);
			callee.calculate(stmDirty, graph);
		}
	}

	public static enum flt_op {
		CEILWS, CEILWD, CEILLS, CEILLD, FLOORWS, FLOORWD, //
		FLOORLS, FLOORLD, ROUNDWS, ROUNDWD, ROUNDLS, ROUNDLD, //
		TRUNCWS, TRUNCWD, TRUNCLS, TRUNCLD, CVTDS, CVTDW, CVTSD, //
		CVTSW, CVTWS, CVTWD, CVTDL, CVTLS, CVTLD, CVTSL, ADDS, ADDD, //
		SUBS, SUBD, DIVS;

		public static flt_op valueOf(int val) {
			if (val >= 0 && val < flt_op.values().length)
				return flt_op.values()[val];
			return null;
		}
	}

	private static HashMap<String, Integer> mipsMask = new HashMap<>();
	static {
		mipsMask.put("FI", 0x00000004);
		mipsMask.put("FU", 0x00000008);
		mipsMask.put("FO", 0x00000010);
		mipsMask.put("FZ", 0x00000020);
		mipsMask.put("FV", 0x00000040);
		mipsMask.put("EI", 0x00000080);
		mipsMask.put("EU", 0x00000100);
		mipsMask.put("EO", 0x00000200);
		mipsMask.put("EZ", 0x00000400);
		mipsMask.put("EV", 0x00000800);
		mipsMask.put("CI", 0x00001000);
		mipsMask.put("CU", 0x00002000);
		mipsMask.put("CO", 0x00004000);
		mipsMask.put("CZ", 0x00008000);
		mipsMask.put("CV", 0x00010000);
		mipsMask.put("CE", 0x00020000);
	}

	private static ComputationNode setMips32FCSRBit(ComputationNode fcsr, ComputationGraph graph, String... flags) {
		int m_cal = 0x0;
		for (String flag : flags) {
			int val = mipsMask.get(flag);
			m_cal = m_cal | val;
		}
		ComputationNode mask = graph.getConstant(32, Integer.toHexString(m_cal));
		ComputationNode orMask = new ComputationNode(VexOperationType.Iop_Or32);
		return graph.addComputationNode(orMask, fcsr, mask);
	}

	public static ComputationNode clearMips32FCSRBits(ComputationNode fcsr, ComputationGraph graph, String... flags) {
		int m_cal = -1;
		for (String flag : flags) {
			int val = ~mipsMask.get(flag);
			m_cal = m_cal & val;
		}
		ComputationNode mask = graph.getConstant(32, Integer.toHexString(m_cal));
		ComputationNode andMask = new ComputationNode(VexOperationType.Iop_And32);
		return graph.addComputationNode(andMask, fcsr, mask);
	}

	private static ComputationNode getMips32FCSRBits(ComputationNode fcsr, ComputationGraph graph, String... flags) {
		int m_val = 0x0;
		for (String flag : flags) {
			int val = mipsMask.get(flag);
			m_val = m_val | val;
		}
		ComputationNode mask = graph.getConstant(32, Integer.toHexString(m_val));
		ComputationNode andMask = new ComputationNode(VexOperationType.Iop_And32);
		return graph.addComputationNode(andMask, fcsr, mask);
	}

	public static ComputationNode getFullBits(ComputationGraph graph, ComputationNode higher, ComputationNode lower) {
		ComputationNode fulBits = graph.getConstant(64, 0x0);
		fulBits = fulBits.cal(VexOperationType.Iop_Or64, graph, higher);
		fulBits = fulBits.calWithVal(VexOperationType.Iop_Shl64, graph, 32);
		fulBits = fulBits.cal(VexOperationType.Iop_Or64, graph, lower);
		return fulBits;
	}

	public static void mips_dirtyhelper_calculate_FCSR_fp32(StmDirty stmDirty, ComputationGraph graph) {
		if (stmDirty.args.size() != 4) {
			logger.error("mips_dirtyhelper_calculate_FCSR_fp32 should have 4 arguments. but {} provided @x0{}",
					stmDirty.args.size(), Long.toHexString(stmDirty.ina));
			return;
		}
		int fs = -1, ft = -1, inst = -1;
		if (!stmDirty.args.get(1).tag.equals(VexExpressionType.Iex_Const)) {
			logger.error("the fs argument for mips_dirtyhelper_calculate_FCSR_fp32 should be constant.");
			return;
		} else
			fs = Integer.parseInt(((ExConst) stmDirty.args.get(1)).constant.value, 16);
		if (!stmDirty.args.get(2).tag.equals(VexExpressionType.Iex_Const)) {
			logger.error("the ft argument for mips_dirtyhelper_calculate_FCSR_fp32 should be constant.");
			return;
		} else
			ft = Integer.parseInt(((ExConst) stmDirty.args.get(2)).constant.value, 16);
		if (!stmDirty.args.get(3).tag.equals(VexExpressionType.Iex_Const)) {
			logger.error("the inst argument for mips_dirtyhelper_calculate_FCSR_fp32 should be constant.");
			return;
		} else
			inst = Integer.parseInt(((ExConst) stmDirty.args.get(3)).constant.value, 16);

		int base = graph.arch.type.getGuestInfo().getRegOffset("f0");
		int loFsVal = base + fs;
		int hiFsVal = base + fs + 1;
		int loFtVal = base + ft;
		int hiFtVal = base + ft + 1;

		ComputationNode loFsReg = graph.getReg(loFsVal, VexVariableType.Ity_I32);
		ComputationNode hiFsReg = graph.getReg(hiFsVal, VexVariableType.Ity_I32);
		ComputationNode loFtReg = graph.getReg(loFtVal, VexVariableType.Ity_I32);
		ComputationNode hiFtReg = graph.getReg(hiFtVal, VexVariableType.Ity_I32);
		
		ComputationNode roundingMode = graph.getConstant(64, 0);

		ComputationNode fcsr = graph.getReg("fcsr", VexVariableType.Ity_D32);
		boolean updated = false;

		// logger.info("{}", flt_op.valueOf(inst));
		switch (flt_op.valueOf(inst)) {
		case ADDD:
		case ADDS: {// Cause bits are ORed into the Flag bits if no exception is
					// taken.
					// ASUME NO EXCEPTION.
			break;
		}
		case CVTWS:
			// Floating Point Convert to Word Fixed Point
			// Float -> Word
		case FLOORWS:
			// Floating Point Floor Convert to Word Fixed Point
			// Float -> Word
		case ROUNDWS:
			// To convert an FP value to 32-bit fixed point, rounding to nearest
			// Float -> Word
		case TRUNCWS:
			// To convert an FP value to 32-bit fixed point, rounding toward
			// zero
			// Float -> Word
		case CEILWS: {
			// Fixed Point Ceiling Convert to Long Fixed Point.
			// Float -> Word
			// source value is Infinity, NaN, or rounds to an integer outside
			// the range -2^31 to 2^31-1, the Invalid Operation flag is set in
			// the FCSR.
			// approximate the result by using only round.
			ComputationNode fullBits = loFsReg;
			fullBits = fullBits.cal(VexOperationType.Iop_ReinterpI32asF32, graph);
			fullBits = fullBits.cal(VexOperationType.Iop_F32toF64, graph);
			fullBits = roundingMode.cal(VexOperationType.Iop_RoundF64toInt, graph, fullBits);
			ComputationNode c1 = fullBits.calWithVal(VexOperationType.Iop_CmpLT64U, graph, (long)Integer.MIN_VALUE);
			ComputationNode c2 = graph.getConstant(64, (long)Integer.MAX_VALUE).cal(VexOperationType.Iop_CmpLT64U, graph,
					fullBits);
			fcsr = graph.createCondition(c1.cal(VexOperationType.Iop_Or32, graph, c2),
					setMips32FCSRBit(fcsr, graph, "CO"), fcsr);
			updated = true;
			break;
		}
		case CVTWD:
			// Floating Point Convert to Word Fixed Point
			// Double -> Word
		case FLOORWD:
			// Floating Point Floor Convert to Word Fixed Point
			// Double -> Word
		case ROUNDWD:
			// To convert an FP value to 32-bit fixed point, rounding to nearest
			// Double -> Word
		case TRUNCWD:
			// To convert an FP value to 32-bit fixed point, rounding toward
			// zero
			// Double -> Word
		case CEILWD: {
			// Fixed Point Ceiling Convert to Long Fixed Point.
			// Double -> Word
			// source value is Infinity, NaN, or rounds to an integer outside
			// the range -2^31 to 2^31-1, the Invalid Operation flag is set in
			// the FCSR.
			// approximate the result by using only round.
			ComputationNode fullBits = getFullBits(graph, hiFsReg, loFsReg);
			fullBits = fullBits.cal(VexOperationType.Iop_ReinterpI64asF64, graph);
			fullBits = roundingMode.cal(VexOperationType.Iop_RoundF64toInt, graph, fullBits);
			ComputationNode c1 = fullBits.calWithVal(VexOperationType.Iop_CmpLT64S, graph, (long) Integer.MIN_VALUE);
			ComputationNode c2 = graph.getConstant(64, (long) Integer.MAX_VALUE).cal(VexOperationType.Iop_CmpLT64S,
					graph, fullBits);
			fcsr = graph.createCondition(c1.cal(VexOperationType.Iop_Or64, graph, c2),
					setMips32FCSRBit(fcsr, graph, "CO"), fcsr);
			updated = true;
			break;
		}
		case CVTLS:
			// Floating Point Convert to Long Fixed Point
			// Float -> Long
		case FLOORLS:
			// Floating Point Floor Convert to Long Fixed Point
			// Float -> Long
		case ROUNDLS:
			// To convert an FP value to 64-bit fixed point, rounding to nearest
			// Float -> Long
		case TRUNCLS:
			// Floating Point Truncate to Long Fixed Point
			// Float -> Long
		case CEILLS: {
			// Fixed Point Ceiling Convert to Long Fixed Point.
			// Float -> Long
			// source value is Infinity, NaN, or rounds to an integer outside
			// the range -2^63 to 2^63-1, the Invalid Operation flag is set in
			// the FCSR.
			// approximate the result by using only round.
			ComputationNode fullBits = loFsReg;
			fullBits = fullBits.cal(VexOperationType.Iop_ReinterpI32asF32, graph);
			fullBits = fullBits.cal(VexOperationType.Iop_F32toF64, graph);
			fullBits = roundingMode.cal(VexOperationType.Iop_RoundF64toInt, graph, fullBits);
			ComputationNode c1 = fullBits.calWithVal(VexOperationType.Iop_CmpLT64S, graph, Long.MIN_VALUE);
			ComputationNode c2 = graph.getConstant(64, Long.MAX_VALUE).cal(VexOperationType.Iop_CmpLT64S, graph,
					fullBits);
			fcsr = graph.createCondition(c1.cal(VexOperationType.Iop_Or64, graph, c2),
					setMips32FCSRBit(fcsr, graph, "CO"), fcsr);
			updated = true;
			break;
		}
		case CVTLD:
			// Floating Point Convert to Long Fixed Point
			// Double -> Long
		case FLOORLD:
			// Floating Point Floor Convert to Long Fixed Point
			// Double -> Long
		case ROUNDLD:
			// To convert an FP value to 64-bit fixed point, rounding to nearest
			// Double -> Long
		case TRUNCLD:
			// Floating Point Truncate to Long Fixed Point
			// Double -> Long
		case CEILLD: {
			// Fixed Point Ceiling Convert to Long Fixed Point.
			// Double -> Long
			// source value is Infinity, NaN, or rounds to an integer outside
			// the range -2^63 to 2^63-1, the Invalid Operation flag is set in
			// the FCSR.
			// approximate the result by using only round.
			ComputationNode fullBits = getFullBits(graph, hiFsReg, loFsReg);
			fullBits = fullBits.cal(VexOperationType.Iop_ReinterpI64asF64, graph);
			fullBits = roundingMode.cal(VexOperationType.Iop_RoundF64toInt, graph, fullBits);
			ComputationNode c1 = fullBits.calWithVal(VexOperationType.Iop_CmpLT64S, graph, Long.MIN_VALUE);
			ComputationNode c2 = graph.getConstant(64, Long.MAX_VALUE).cal(VexOperationType.Iop_CmpLT64S, graph,
					fullBits);
			fcsr = graph.createCondition(c1.cal(VexOperationType.Iop_Or64, graph, c2),
					setMips32FCSRBit(fcsr, graph, "CO"), fcsr);
			updated = true;
			break;
		}
		case CVTDL:
		case CVTDS:
		case CVTDW: {
			// (long, word, float) Convert to Double Floating Point
			// converted to a value in single floating point format and rounded
			// according to the current rounding mode in FCSR.
			// no FCSR set bits.
			break;
		}
		case CVTSD:
		case CVTSL:
		case CVTSW: {
			// (double, long, word) Convert to Single Floating Point
			// no FCSR set bits in the manual
		}
		case DIVS: {
			loFsReg = loFsReg.cal(VexOperationType.Iop_ReinterpI32asF32, graph);
			loFtReg = loFtReg.cal(VexOperationType.Iop_ReinterpI32asF32, graph);
			ComputationNode fullBitsFs = loFsReg.cal(VexOperationType.Iop_F32toF64, graph);
			ComputationNode fullBitsFt = loFtReg.cal(VexOperationType.Iop_F32toF64, graph);
			// divided-by-zero:
			ComputationNode dividedByZero = loFtReg.calWithVal(VexOperationType.Iop_CasCmpEQ64, graph, 0x0);
			fcsr = graph.createCondition(dividedByZero, setMips32FCSRBit(fcsr, graph, "CZ"), fcsr);

			ComputationNode result = roundingMode.cal(VexOperationType.Iop_DivF64, graph, fullBitsFs, fullBitsFt);
			// overflow:
			ComputationNode cond1 = result.calWithVal(VexOperationType.Iop_CmpLT64Fx2, graph, Float.MIN_VALUE);
			fcsr = graph.createCondition(cond1, setMips32FCSRBit(fcsr, graph, "CO"), fcsr);
			// underflow:
			ComputationNode cond2 = graph.getConstant(64, Long.toHexString(Double.doubleToLongBits(Float.MAX_VALUE)))
					.cal(VexOperationType.Iop_CmpLT64Fx2, graph, result);
			fcsr = graph.createCondition(cond2, setMips32FCSRBit(fcsr, graph, "CU"), fcsr);
			updated = true;
			break;
		}
		case SUBD:
			break;
		case SUBS: {
			loFsReg = loFsReg.cal(VexOperationType.Iop_ReinterpI32asF32, graph);
			loFtReg = loFtReg.cal(VexOperationType.Iop_ReinterpI32asF32, graph);
			ComputationNode fullBitsFs = loFsReg.cal(VexOperationType.Iop_F32toF64, graph);
			ComputationNode fullBitsFt = loFtReg.cal(VexOperationType.Iop_F32toF64, graph);
			ComputationNode result = roundingMode.cal(VexOperationType.Iop_SubF64, graph, fullBitsFs, fullBitsFt);
			// overflow:
			ComputationNode cond1 = result.calWithVal(VexOperationType.Iop_CmpLT64Fx2, graph, Float.MIN_VALUE);
			fcsr = graph.createCondition(cond1, setMips32FCSRBit(fcsr, graph, "CO"), fcsr);
			// underflow:
			ComputationNode cond2 = graph.getConstant(64, Long.toHexString(Double.doubleToLongBits(Float.MAX_VALUE)))
					.cal(VexOperationType.Iop_CmpLT64Fx2, graph, result);
			fcsr = graph.createCondition(cond2, setMips32FCSRBit(fcsr, graph, "CU"), fcsr);
			updated = true;
			break;
		}
		default:
			logger.error("Unsupported instruction {} in mips_dirtyhelper_calculate_FCSR_fp32", inst);
			break;
		}
		// get enable bits:
		if (updated) {
			ComputationNode eBits = getMips32FCSRBits(fcsr, graph, "EI", "EU", "EO", "EZ", "EV")
					.calWithVal(VexOperationType.Iop_Shr32, graph, (0x00000080 - 0x00000004));
			ComputationNode cBits = getMips32FCSRBits(fcsr, graph, "CI", "CU", "CO", "CZ", "CV")
					.calWithVal(VexOperationType.Iop_Shr32, graph, (0x00001000 - 0x00000004));

			fcsr = fcsr.cal(VexOperationType.Iop_Or32, graph, cBits.cal(VexOperationType.Iop_And32, graph, eBits));
		}

		ComputationNode tmpVal = graph.getTmpVar(stmDirty.tmp_unsigned);
		graph.assignValue(fcsr, tmpVal);
	}

	public static ComputationNode x86g_dirtyhelper_CPUID_sse0(StmDirty stmDirty, ComputationGraph graph) {
		ComputationNode eax = graph.getReg("eax", graph.arch.type.defaultTypte());
		ComputationNode ecx = graph.getReg("ecx", graph.arch.type.defaultTypte());
		ComputationNode edx = graph.getReg("edx", graph.arch.type.defaultTypte());
		ComputationNode ebx = graph.getReg("ebx", graph.arch.type.defaultTypte());

		ComputationNode cond = eax.calWithVal(VexOperationType.Iop_CmpEQ32, graph, 0);

		ComputationNode n_eax = graph.createCondition(cond, 0x1, 0x543);
		ComputationNode n_ebx = graph.createCondition(cond, 0x72676e41, 0x0);
		ComputationNode n_ecx = graph.createCondition(cond, 0x21444955, 0x0);
		ComputationNode n_edx = graph.createCondition(cond, 0x50432079, 0x8001bf);

		graph.assignValue(n_eax, eax);
		graph.assignValue(n_ebx, ecx);
		graph.assignValue(n_ecx, edx);
		graph.assignValue(n_edx, ebx);

		return null;
	}

	public static ComputationNode x86g_dirtyhelper_IN(StmDirty stmDirty, ComputationGraph graph) {
		// do nothing. getting value in. Unconstrained valuable
		ComputationNode e_sz = stmDirty.args.get(stmDirty.args.size() - 1).getNode(graph, stmDirty.ina).resolve(graph,
				true);
		long size = 0;
		if (e_sz.isConst()) {
			size = e_sz.constant.getVal() * 8;
		} else
			size = 32;
		if (size != 32 && size != 16 && size != 8)
			size = 32;
		return graph.getRegUnconstrained(stmDirty.ina, "in", VexVariableType.getIntType((int) size));
	}

	public static ComputationNode x86g_dirtyhelper_OUT(StmDirty stmDirty, ComputationGraph graph) {
		// sending signals. do nothing.
		return null;
	}

	public static ComputationNode x86g_dirtyhelper_storeF80le(StmDirty stmDirty, ComputationGraph graph) {
		ComputationNode data = stmDirty.args.get(stmDirty.args.size() - 1).getNode(graph, stmDirty.ina);
		ComputationNode addr = stmDirty.args.get(stmDirty.args.size() - 2).getNode(graph, stmDirty.ina);

		// little endian: start the read with the first 64 bits (lower)

		{
			// generate the lower 64 bits
			TypeInformation type2 = new TypeInformation();
			type2.argType.add(VexVariableType.Ity_I64);
			type2.outputType = VexVariableType.Ity_I64;
			ComputationNode mantissa_cal = new ComputationNode(NodeType.calculate, type2);
			mantissa_cal.ccall_oprName = "convert_f64le_to_f80le_64";
			ComputationNode comp = graph.addComputationNode(mantissa_cal, data);
			graph.memory.writeMem(addr, comp, VexEndnessType.VexEndnessLE, graph);
		}

		{
			// generate the higher 16 bits
			TypeInformation type1 = new TypeInformation();
			type1.argType.add(VexVariableType.Ity_I64);
			type1.outputType = VexVariableType.Ity_I16;
			ComputationNode sign_and_exponent_cal = new ComputationNode(NodeType.calculate, type1);
			sign_and_exponent_cal.ccall_oprName = "convert_f64le_to_f80le_16";
			ComputationNode comp = graph.addComputationNode(sign_and_exponent_cal, data);
			graph.memory.writeMem(addr.calWithVal(VexOperationType.Iop_Add32, graph, 64), comp,
					VexEndnessType.VexEndnessLE, graph);

		}

		// no return value.
		return null;
	}

	public static ComputationNode x86g_dirtyhelper_loadF80le(StmDirty stmDirty, ComputationGraph graph) {
		ComputationNode addr = stmDirty.args.get(stmDirty.args.size() - 1).getNode(graph, stmDirty.ina);
		// read lower 64 bits
		ComputationNode lower = graph.memory.readMem(-1, addr, VexVariableType.Ity_I64, VexEndnessType.VexEndnessLE,
				graph);
		// read higher 16 bits
		ComputationNode higher = graph.memory.readMem(-1, addr.calWithVal(VexOperationType.Iop_Add32, graph, 64),
				VexVariableType.Ity_I16, VexEndnessType.VexEndnessLE, graph);

		// (16, 64) -> 64
		TypeInformation type1 = new TypeInformation();
		type1.argType.add(VexVariableType.Ity_I16);
		type1.argType.add(VexVariableType.Ity_I64);
		type1.outputType = VexVariableType.Ity_I64;
		ComputationNode cal = new ComputationNode(NodeType.calculate, type1);
		cal.ccall_oprName = "convert_f64le_to_f80le";
		ComputationNode comp = graph.addComputationNode(cal, higher, lower);

		ComputationNode tmpVal = graph.getTmpVar(stmDirty.tmp_unsigned);
		graph.assignValue(comp, tmpVal);
		return tmpVal;
	}

}
