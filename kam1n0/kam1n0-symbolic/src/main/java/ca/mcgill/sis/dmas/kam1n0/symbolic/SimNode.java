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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecNum;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FPExpr;
import com.microsoft.z3.FPRMExpr;
import com.microsoft.z3.FPSort;
import com.microsoft.z3.Model;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import ca.mcgill.sis.dmas.kam1n0.symbolic.run.Assignment;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.RoundingMode;

public class SimNode {

	private static Logger logger = LoggerFactory.getLogger(SimNode.class);

	public transient Context ctx;
	public BitVecExpr e;
	public VexVariableType t;

	public static SimNode concate(Context ctx, SimNode... nodes) {
		BitVecExpr first = nodes[0].e;
		for (int i = 1; i < nodes.length; ++i) {
			first = ctx.mkConcat(first, nodes[i].e);
		}
		return new SimNode(ctx, first, VexVariableType.getIntType(first.getSortSize()));
	}

	public SimNode concate(SimNode node) {
		BitVecExpr first = ctx.mkConcat(e, node.e);
		return new SimNode(ctx, first, VexVariableType.getIntType(first.getSortSize()));
	}

	public SimNode ite(SimNode ifthen, SimNode elsedo) {
		BoolExpr ifExprCmpZero = ctx.mkNot(ctx.mkEq(this.e, ctx.mkBV(0x0, this.size())));
		Expr ne = ctx.mkITE(ifExprCmpZero, ifthen.e, elsedo.e);
		return new SimNode(ctx, (BitVecExpr) ne, this.t);
	}

	public BoolExpr isTrue() {
		BoolExpr ifExprCmpZero = ctx.mkNot(ctx.mkEq(this.e, ctx.mkBV(0x0, this.size())));
		return ifExprCmpZero;
	}

	@SuppressWarnings("unchecked")
	public <T extends Expr> T ite(T ifthen, T elsedo) {
		BoolExpr ifExprCmpZero = ctx.mkNot(ctx.mkEq(this.e, ctx.mkBV(0x0, this.size())));
		Expr ne = ctx.mkITE(ifExprCmpZero, ifthen, elsedo);
		return (T) ne;
	}

	public SimNode ite(int ifthen, int elsedo) {
		return ite(SimNode.val(ctx, ifthen, size()), SimNode.val(ctx, elsedo, size()));
	}

	public SimNode ite(SimNode ifthen, int elsedo) {
		return ite(ifthen, SimNode.val(ctx, elsedo, size()));
	}

	public SimNode ite(int ifthen, SimNode elsedo) {
		return ite(SimNode.val(ctx, ifthen, size()), elsedo);
	}

	public static SimNode zero(Context ctx, int bits) {
		return new SimNode(ctx, ctx.mkBV(0x0, bits), VexVariableType.getIntType(bits));
	}

	public static SimNode val(Context ctx, long val, int bits) {
		return new SimNode(ctx, ctx.mkBV(val, bits), VexVariableType.getIntType(bits));
	}

	public static SimNode one(Context ctx, int bits) {
		return new SimNode(ctx, ctx.mkBV(0x1, bits), VexVariableType.getIntType(bits));
	}

	public static SimNode ones(Context ctx, int bits) {
		return new SimNode(ctx, ctx.mkBV(-1, bits), VexVariableType.getIntType(bits));
	}

	public static SimNode val(Context ctx, double val, int bits) {
		return new SimNode(ctx, toRawBV(ctx, ctx.mkFP(val, getSort(ctx, bits))), VexVariableType.getFltType(bits));
	}

	public SimNode(Context ctx, BitVecExpr bExp, VexVariableType outputType) {
		this.ctx = ctx;
		this.e = bExp;
		this.t = outputType;
		// if(this.size() != outputType.numOfBit()){
		// System.out.println("");
		// }
		// assert this.size() == outputType.numOfBit();
	}

	public SimNode(Context ctx, String variable, VexVariableType outputType) {
		this.ctx = ctx;
		this.e = ctx.mkBVConst(variable, outputType.numOfBit());
		this.t = outputType;
	}

	public SimNode(Context ctx, long value, VexVariableType outputType) {
		this.ctx = ctx;
		this.e = ctx.mkBV(value, outputType.numOfBit());
		this.t = outputType;
	}

	public int size() {
		return e.getSortSize();
	}

	public SimNode mkCompatible(SimNode target, boolean signed) {
		if (size() < target.size()) {
			if (!signed)
				return this.zeroExtend(target.size());
			else
				return this.signExtend(target.size());
		}
		return this;
	}

	@Override
	public String toString() {
		return t.shortString() + ":" + t.numOfBit() + "-" + e.toString();
	}

	public SimNode to(VexVariableType type, boolean signed, String fromSide) {
		return Z3Box.convert(ctx, this, type, signed, fromSide, null, null);
	}

	public SimNode to(VexVariableType type, boolean signed) {
		return to(type, signed, null);
	}

	public SimNode to(int bits) {
		if (this.size() > bits) {
			return this.extract(bits - 1, 0);
		}
		if (this.size() < bits) {
			return this.zeroExtend(bits);
		}
		return this;
	}

	public SimNode zeroExtend(int toBits) {
		if (toBits > size()) {
			BitVecExpr ne = ctx.mkZeroExt(toBits - size(), e);
			return new SimNode(ctx, ne, VexVariableType.getIntType(toBits));
		} else if (toBits == size()) {
			return this;
		} else {
			logger.error("To size is bigger than from size...");
			return null;
		}
	}

	public SimNode signExtend(int toBits) {
		if (toBits > size()) {
			BitVecExpr ne = ctx.mkSignExt(toBits - size(), e);
			return new SimNode(ctx, ne, VexVariableType.getIntType(toBits));
		} else if (toBits == size()) {
			return this;
		} else {
			logger.error("To size is bigger than from size...");
			return null;
		}
	}

	public SimNode extract(int hi, int lw) {
		return new SimNode(ctx, ctx.mkExtract(hi, lw, e), VexVariableType.getIntType(hi - lw + 1));
	}

	public SimNode extract(SimNode hi, SimNode lw) {
		if (lw.size() != size())
			lw.zeroExtend(size());
		SimNode result = this.shr(lw);
		SimNode mask = SimNode.val(ctx, -1, size()).shr(hi.neg().add(size()));
		return result.and(mask);
	}

	public SimNode extract(SimNode hi, int lw) {
		SimNode result = this.shr(lw);
		SimNode mask = SimNode.val(ctx, -1, size()).shr(hi.neg().add(size()));
		return result.and(mask);
	}

	public SimNode bitAt(int hi) {
		if (hi >= size()) {
			System.out.println("");
		}
		return new SimNode(ctx, ctx.mkExtract(hi, hi, e), VexVariableType.Ity_I1).zeroExtend(t.numOfBit());
	}

	public SimNode bitAt(SimNode hi) {
		SimNode arg0 = this.mkCompatible(hi, false);
		SimNode arg1 = hi.mkCompatible(this, false);
		return arg0.shr(arg1).and(0x1);
	}

	public SimNode sign() {
		return bitAt(size() - 1);
	}

	// bit operations
	public SimNode xor(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVXOR(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode xor(int val) {
		BitVecExpr exp = ctx.mkBVXOR(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode or(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVOR(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode or(int val) {
		BitVecExpr exp = ctx.mkBVOR(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode or(long val) {
		BitVecExpr exp = ctx.mkBVOR(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode and(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVAND(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode and(int val) {
		BitVecExpr exp = ctx.mkBVAND(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode and(long val) {
		BitVecExpr exp = ctx.mkBVAND(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode not() {
		BitVecExpr exp = ctx.mkBVNot(e);
		return new SimNode(ctx, exp, t);
	}

	public SimNode clz() {
		SimNode counter = SimNode.zero(ctx, size());
		for (int i = 0; i < t.numOfBit(); ++i) {
			SimNode bit = this.extract(i, i).zeroExtend(size());
			counter = bit.cmpeq(0x1).ite(SimNode.val(ctx, t.numOfBit() - i - 1, size()), counter);
		}
		return counter;
	}

	public SimNode ctz() {
		SimNode counter = SimNode.zero(ctx, size());
		for (int i = t.numOfBit() - 1; i >= 0; --i) {
			SimNode bit = this.extract(i, i).zeroExtend(size());
			counter = bit.cmpeq(0x1).ite(SimNode.val(ctx, i, size()), counter);
		}
		return counter;
	}

	// cmp general:
	public SimNode cmpeq(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BoolExpr condition = ctx.mkEq(arg1.e, arg2.e);
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, arg1.size()), ctx.mkBV(0, arg1.size()));
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmpeq(int val) {
		BoolExpr condition = ctx.mkEq(e, ctx.mkBV(val, size()));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpeq(long val) {
		BoolExpr condition = ctx.mkEq(e, ctx.mkBV(val, size()));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpne(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BoolExpr condition = ctx.mkNot(ctx.mkEq(arg1.e, arg2.e));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, arg1.size()), ctx.mkBV(0, arg1.size()));
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmpne(int val) {
		BoolExpr condition = ctx.mkNot(ctx.mkEq(e, ctx.mkBV(val, size())));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpne(long val) {
		BoolExpr condition = ctx.mkNot(ctx.mkEq(e, ctx.mkBV(val, size())));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpnez() {
		BoolExpr condition = ctx.mkNot(ctx.mkEq(e, ctx.mkBV(0x0, t.numOfBit())));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpgt(SimNode node, boolean signed) {
		SimNode arg1 = this.mkCompatible(node, signed);
		SimNode arg2 = node.mkCompatible(this, signed);
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSGT(arg1.e, arg2.e);
		} else {
			condition = ctx.mkBVUGT(arg1.e, arg2.e);
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, arg1.size()), ctx.mkBV(0, arg1.size()));
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmpgt(int val, boolean signed) {
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSGT(e, ctx.mkBV(val, size()));
		} else {
			condition = ctx.mkBVUGT(e, ctx.mkBV(val, size()));
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpge(SimNode node, boolean signed) {
		SimNode arg1 = this.mkCompatible(node, signed);
		SimNode arg2 = node.mkCompatible(this, signed);
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSGE(arg1.e, arg2.e);
		} else {
			condition = ctx.mkBVUGE(arg1.e, arg2.e);
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, arg1.size()), ctx.mkBV(0, arg1.size()));
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmpge(int val, boolean signed) {
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSGE(e, ctx.mkBV(val, size()));
		} else {
			condition = ctx.mkBVUGE(e, ctx.mkBV(val, size()));
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmplt(SimNode node, boolean signed) {
		SimNode arg1 = this.mkCompatible(node, signed);
		SimNode arg2 = node.mkCompatible(this, signed);
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSLT(arg1.e, arg2.e);
		} else {
			condition = ctx.mkBVULT(arg1.e, arg2.e);
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, arg1.size()), ctx.mkBV(0, arg1.size()));
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmplt(int val, boolean signed) {
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSLT(e, ctx.mkBV(val, size()));
		} else {
			condition = ctx.mkBVULT(e, ctx.mkBV(val, size()));
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmple(SimNode node, boolean signed) {
		SimNode arg1 = this.mkCompatible(node, signed);
		SimNode arg2 = node.mkCompatible(this, signed);
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSLE(arg1.e, arg2.e);
		} else {
			condition = ctx.mkBVULE(arg1.e, arg2.e);
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, arg1.size()), ctx.mkBV(0, arg1.size()));
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmple(int val, boolean signed) {
		BoolExpr condition;
		if (signed) {
			condition = ctx.mkBVSLE(e, ctx.mkBV(val, size()));
		} else {
			condition = ctx.mkBVULE(e, ctx.mkBV(val, size()));
		}
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode cmpord(SimNode node, boolean signed) {
		SimNode arg1 = this.mkCompatible(node, signed);
		SimNode arg2 = node.mkCompatible(this, signed);
		BitVecExpr exp;
		if (signed) {
			exp = (BitVecExpr) ctx.mkITE(//
					ctx.mkEq(arg1.e, arg2.e), //
					ctx.mkBV(0x2, arg1.size()), //
					ctx.mkITE(//
							ctx.mkBVSLT(arg1.e, arg2.e), //
							ctx.mkBV(0x8, arg1.size()), //
							ctx.mkBV(0x4, arg1.size())));
		} else {
			exp = (BitVecExpr) ctx.mkITE(//
					ctx.mkEq(arg1.e, arg2.e), //
					ctx.mkBV(0x2, arg1.size()), //
					ctx.mkITE(//
							ctx.mkBVULT(arg1.e, arg2.e), //
							ctx.mkBV(0x8, arg1.size()), //
							ctx.mkBV(0x4, arg1.size())));
		}
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode cmpord(int val, boolean signed) {
		BitVecExpr node = ctx.mkBV(val, size());
		BitVecExpr exp;
		if (signed) {
			exp = (BitVecExpr) ctx.mkITE(//
					ctx.mkEq(e, node), //
					ctx.mkBV(0x2, t.numOfBit()), //
					ctx.mkITE(//
							ctx.mkBVSLT(e, node), //
							ctx.mkBV(0x8, t.numOfBit()), //
							ctx.mkBV(0x4, t.numOfBit())));
		} else {
			exp = (BitVecExpr) ctx.mkITE(//
					ctx.mkEq(e, node), //
					ctx.mkBV(0x2, t.numOfBit()), //
					ctx.mkITE(//
							ctx.mkBVULT(e, node), //
							ctx.mkBV(0x8, t.numOfBit()), //
							ctx.mkBV(0x4, t.numOfBit())));
		}
		return new SimNode(ctx, exp, t);
	}

	// algorithmic operation
	public SimNode add(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVAdd(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode add(int val) {
		BitVecExpr exp = ctx.mkBVAdd(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode qadd(SimNode node) {
		return this.add(node);
	}

	public SimNode qadd(int val) {
		return this.add(val);
	}

	public SimNode sub(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVSub(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode sub(int val) {
		BitVecExpr exp = ctx.mkBVSub(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode mul(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVMul(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode mul(int val) {
		BitVecExpr exp = ctx.mkBVMul(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode mull(SimNode node, VexVariableType outputType, boolean isSigned) {
		SimNode arg0 = Z3Box.convert(ctx, this, outputType, isSigned, null, null, null);
		SimNode arg1 = Z3Box.convert(ctx, node, outputType, isSigned, null, null, null);
		return arg0.mul(arg1);
	}

	public SimNode div(SimNode node, boolean signed) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp;
		if (signed)
			exp = ctx.mkBVSDiv(arg1.e, arg2.e);
		else
			exp = ctx.mkBVUDiv(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode div(int val, boolean signed) {
		BitVecExpr exp;
		if (signed)
			exp = ctx.mkBVSDiv(e, ctx.mkBV(val, size()));
		else
			exp = ctx.mkBVUDiv(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode mod(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp;
		exp = ctx.mkBVSMod(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode mod(int val) {
		BitVecExpr exp;
		exp = ctx.mkBVSMod(e, ctx.mkBV(val, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode neg() {
		BitVecExpr exp = ctx.mkBVNeg(e);
		return new SimNode(ctx, exp, t);
	}

	public SimNode abs() {
		BitVecExpr exp = Z3Box.ABS(ctx, e);
		return new SimNode(ctx, exp, t);
	}

	public SimNode shl(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVSHL(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode shl(int bits) {
		BitVecExpr exp = ctx.mkBVSHL(e, ctx.mkBV(bits, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode shr(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVLSHR(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode shr(int bits) {
		BitVecExpr exp = ctx.mkBVLSHR(e, ctx.mkBV(bits, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode sar(SimNode node) {
		SimNode arg1 = this.mkCompatible(node, false);
		SimNode arg2 = node.mkCompatible(this, false);
		BitVecExpr exp = ctx.mkBVASHR(arg1.e, arg2.e);
		return new SimNode(ctx, exp, arg1.t);
	}

	public SimNode sar(int bits) {
		BitVecExpr exp = ctx.mkBVASHR(e, ctx.mkBV(bits, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode simplify() {
		BitVecExpr exp = (BitVecExpr) this.e.simplify();
		return new SimNode(ctx, exp, t);
	}

	public SimNode setValues(List<Assignment> vals) {
		BitVecExpr exp = e;
		for (Assignment ent : vals) {
			long val = Long.parseUnsignedLong(ent.value, 16);
			int num_bits = ent.sym.sNode.t.numOfBit();
			long mask = -1;
			if (num_bits < 64)
				mask = ~(-1l << num_bits);
			exp = (BitVecExpr) exp.substitute(ent.sym.sNode.e, ctx.mkBV(val & mask, ent.sym.sNode.size()));
		}
		return new SimNode(ctx, exp, t);
	}

	public SimNode subtitute(SimNode toBeReplaced, SimNode replacemenet) {
		BitVecExpr exp = (BitVecExpr) e.substitute(toBeReplaced.e, replacemenet.e);
		return new SimNode(ctx, exp, t);
	}

	public SimNode setValues(SimNode old, int newVar) {
		BitVecExpr exp = e;
		int num_bits = old.size();
		long mask = -1;
		if (num_bits < 64)
			mask = ~(-1l << num_bits);
		exp = (BitVecExpr) exp.substitute(old.e, ctx.mkBV(newVar & mask, old.size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode setValues(SimNode old, long newVar) {
		BitVecExpr exp = e;
		int num_bits = old.size();
		long mask = -1;
		if (num_bits < 64)
			mask = ~(-1l << num_bits);
		exp = (BitVecExpr) exp.substitute(old.e, ctx.mkBV(newVar & mask, old.size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode toFloat(int bits) {
		return toFloat(bits, true, RoundingMode.def());
	}

	public SimNode toFloat(int bits, RoundingMode rm) {
		return toFloat(bits, true, rm);
	}

	public SimNode toFloat(int bits, Boolean signed, RoundingMode rm) {
		if (signed == null)
			signed = true;
		if (isFloat()) {
			FPExpr fp = this.toRawFloat();
			FPRMExpr ms = getRM(rm);
			FPExpr nfp = ctx.mkFPToFP(ms, fp, getSort(bits));
			BitVecExpr ne = toRawBV(nfp);
			return new SimNode(ctx, ne, VexVariableType.getFltType(bits));
		} else {
			FPRMExpr ms = getRM(rm);
			FPExpr nf = ctx.mkFPToFP(ms, this.e, getSort(bits), signed);
			BitVecExpr ne = toRawBV(nf);
			return new SimNode(ctx, ne, VexVariableType.getFltType(bits));
		}
	}

	public SimNode toFloat(int bits, Boolean signed, SimNode rm) {
		if (signed == null)
			signed = true;
		FPRMExpr ms = rm.toRm();
		if (isFloat()) {
			FPExpr fp = this.toRawFloat();
			FPExpr nfp = ctx.mkFPToFP(ms, fp, getSort(bits));
			BitVecExpr ne = toRawBV(nfp);
			return new SimNode(ctx, ne, VexVariableType.getFltType(bits));
		} else {
			FPExpr nf = ctx.mkFPToFP(ms, this.e, getSort(bits), signed);
			BitVecExpr ne = toRawBV(nf);
			return new SimNode(ctx, ne, VexVariableType.getFltType(bits));
		}
	}

	private FPSort getSort(int bits) {
		return getSort(ctx, bits);
	}

	public static FPSort getSort(Context ctx, int bits) {
		switch (bits) {
		case 16:
			return ctx.mkFPSort16();
		case 32:
			return ctx.mkFPSort32();
		case 64:
			return ctx.mkFPSort64();
		default:
			logger.error("Invalid bit size for fsort:" + bits);
			return ctx.mkFPSort32();
		}
	}

	public static FPRMExpr getRM(Context ctx, RoundingMode rm) {
		FPRMExpr ms;
		switch (rm) {
		case RM: // RM_RTN // Z3_OP_FPA_RM_TOWARD_NEGATIVE // 01b
			ms = ctx.mkFPRoundTowardNegative();
			break;
		case RN: // RM_RNE // Z3_OP_FPA_RM_NEAREST_TIES_TO_EVEN // 00b
			ms = ctx.mkFPRoundNearestTiesToEven();
			break;
		case RP: // RM_RTP // Z3_OP_FPA_RM_TOWARD_POSITIVE // 10b
			ms = ctx.mkFPRoundTowardPositive();
			break;
		case RZ: // RM_RTZ // Z3_OP_FPA_RM_TOWARD_ZERO // 11b
			ms = ctx.mkFPRoundTowardZero();
			break;
		default:
			ms = ctx.mkFPRoundNearestTiesToEven(); // RM_RNE
			break;
		}
		return ms;
	}

	public FPRMExpr toRm() {
		FPRMExpr deF = ctx.mkFPRoundNearestTiesToEven();
		FPRMExpr ms = deF;
		ms = this.cmpeq(0).ite(ctx.mkFPRoundNearestTiesToEven(), ms);
		ms = this.cmpeq(1).ite(ctx.mkFPRoundTowardNegative(), ms);
		ms = this.cmpeq(2).ite(ctx.mkFPRoundTowardPositive(), ms);
		ms = this.cmpeq(3).ite(ctx.mkFPRoundTowardZero(), ms);
		return ms;
	}

	private FPRMExpr getRM(RoundingMode rm) {
		return getRM(ctx, rm);
	}

	public SimNode toInt(int bits, Boolean signed, RoundingMode rm) {
		if (!isFloat())
			return this;
		if (signed == null)
			signed = true;
		FPExpr fp = toRawFloat();
		FPRMExpr ms = getRM(rm);
		BitVecExpr ne = ctx.mkFPToBV(ms, fp, bits, signed);
		return new SimNode(ctx, ne, VexVariableType.getIntType(bits));
	}

	public SimNode toInt(int bits, Boolean signed, SimNode rm) {
		if (!isFloat())
			return this;
		if (signed == null)
			signed = true;
		FPExpr fp = toRawFloat();
		FPRMExpr ms = rm.toRm();
		BitVecExpr ne = ctx.mkFPToBV(ms, fp, bits, signed);
		return new SimNode(ctx, ne, VexVariableType.getIntType(bits));
	}

	public FPExpr toRawFloat() {
		if (size() == 64) {
			FPSort sort = ctx.mkFPSort64();
			FPExpr fp2 = ctx.mkFPToFP(e, sort);
			return fp2;
		} else if (size() == 32) {
			FPSort sort = ctx.mkFPSort32();
			FPExpr fp2 = ctx.mkFPToFP(e, sort);
			return fp2;
		} else if (size() == 16) {
			FPSort sort = ctx.mkFPSort16();
			FPExpr fp2 = ctx.mkFPToFP(e, sort);
			return fp2;
		} else
			logger.error("Can't convert {} vectors to float.", size());
		return null;
	}

	private BitVecExpr toRawBV(FPExpr fp) {
		return toRawBV(ctx, fp);
	}

	private static BitVecExpr toRawBV(Context ctx, FPExpr fp) {
		BitVecExpr bv = ctx.mkFPToIEEEBV(fp);
		return bv;
	}

	public boolean isFloat() {
		return t.isF();
	}

	public SimNode fpCmp(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		SimNode val = SimNode.val(ctx, 0x45, size());
		val = this.fpLt(node).ite(SimNode.val(ctx, 0x01, size()), val);
		val = this.fpGt(node).ite(SimNode.val(ctx, 0x00, size()), val);
		val = this.fpEq(node).ite(SimNode.val(ctx, 0x40, size()), val);
		return val;
	}

	public SimNode fpEq(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		BoolExpr condition = ctx.mkFPEq(arg0, arg1);
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpNeq(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		BoolExpr condition = ctx.mkNot(ctx.mkFPEq(arg0, arg1));
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpGt(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		BoolExpr condition = ctx.mkFPGt(arg0, arg1);
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpGe(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		BoolExpr condition = ctx.mkFPGEq(arg0, arg1);
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpLt(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		BoolExpr condition = ctx.mkFPLt(arg0, arg1);
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpLe(SimNode node) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		BoolExpr condition = ctx.mkFPLEq(arg0, arg1);
		BitVecExpr exp = (BitVecExpr) ctx.mkITE(condition, ctx.mkBV(1, size()), ctx.mkBV(0, size()));
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpAbs() {
		if (!this.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr result = ctx.mkFPAbs(arg0);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpNeg() {
		if (!this.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPExpr arg0 = this.toRawFloat();
		FPExpr result = ctx.mkFPNeg(arg0);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpSub(SimNode node, RoundingMode mode) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPSub(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpSub(SimNode node, SimNode mode) {
		if (!this.isFloat() || !node.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPSub(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpAdd(SimNode node, RoundingMode mode) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPAdd(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpAdd(SimNode node, SimNode mode) {
		if (!this.isFloat() || !node.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPAdd(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpMul(SimNode node, RoundingMode mode) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPMul(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpMul(SimNode node, SimNode mode) {
		if (!this.isFloat() || !node.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPMul(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpDiv(SimNode node, RoundingMode mode) {
		if (!this.isFloat() || !node.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPDiv(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpDiv(SimNode node, SimNode mode) {
		if (!this.isFloat() || !node.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr result = ctx.mkFPDiv(ms, arg0, arg1);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpSqrt(SimNode mode) {
		if (!this.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg0 = this.toRawFloat();
		FPExpr result = ctx.mkFPSqrt(ms, arg0);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpSqrt(RoundingMode mode) {
		if (!this.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg0 = this.toRawFloat();
		FPExpr result = ctx.mkFPSqrt(ms, arg0);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	// :: IRRoundingMode(I32) x F32 x F32 x F32 -> F32 (computes arg2 * arg3 +/-
	// arg4)
	public SimNode fpMAdd(SimNode arg3n, SimNode arg4n, SimNode mode) {
		if (!this.isFloat() || !arg3n.isFloat() || !arg4n.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg2 = this.toRawFloat();
		FPExpr arg3 = arg3n.toRawFloat();
		FPExpr arg4 = arg4n.toRawFloat();
		FPExpr result = ctx.mkFPAdd(ms, ctx.mkFPMul(ms, arg2, arg3), arg4);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpMAdd(SimNode arg3n, SimNode arg4n, RoundingMode mode) {
		if (!this.isFloat() || !arg3n.isFloat() || !arg4n.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg2 = this.toRawFloat();
		FPExpr arg3 = arg3n.toRawFloat();
		FPExpr arg4 = arg4n.toRawFloat();
		FPExpr result = ctx.mkFPAdd(ms, ctx.mkFPMul(ms, arg2, arg3), arg4);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpMSub(SimNode arg3n, SimNode arg4n, SimNode mode) {
		if (!this.isFloat() || !arg3n.isFloat() || !arg4n.isFloat() || mode.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = mode.toRm();
		FPExpr arg2 = this.toRawFloat();
		FPExpr arg3 = arg3n.toRawFloat();
		FPExpr arg4 = arg4n.toRawFloat();
		FPExpr result = ctx.mkFPSub(ms, ctx.mkFPMul(ms, arg2, arg3), arg4);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpMSub(SimNode arg3n, SimNode arg4n, RoundingMode mode) {
		if (!this.isFloat() || !arg3n.isFloat() || !arg4n.isFloat()) {
			logger.error("Both node needs to be float!");
			return null;
		}
		FPRMExpr ms = getRM(mode);
		FPExpr arg2 = this.toRawFloat();
		FPExpr arg3 = arg3n.toRawFloat();
		FPExpr arg4 = arg4n.toRawFloat();
		FPExpr result = ctx.mkFPSub(ms, ctx.mkFPMul(ms, arg2, arg3), arg4);
		BitVecExpr ne = toRawBV(result);
		return new SimNode(ctx, ne, t);
	}

	public SimNode fpMin(SimNode node) {
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr re = ctx.mkFPMin(arg0, arg1);
		BitVecExpr exp = toRawBV(re);
		return new SimNode(ctx, exp, t);
	}

	public SimNode fpMax(SimNode node) {
		FPExpr arg0 = this.toRawFloat();
		FPExpr arg1 = node.toRawFloat();
		FPExpr re = ctx.mkFPMax(arg0, arg1);
		BitVecExpr exp = toRawBV(re);
		return new SimNode(ctx, exp, t);
	}

	public SimNode setLo(SimNode val) {
		assert val.size() <= size();
		if (val.size() == size())
			return val;
		return set(val.size() - 1, 0, val);
	}

	public SimNode set(int hi, int lo, SimNode val) {
		return SimNode.ones(ctx, hi - lo + 1).zeroExtend(size()).not().and(this).or(val.zeroExtend(size()));
	}

	public SimNode reinerpret(VexVariableType type) {
		return new SimNode(ctx, e, type);
	}

	public SimNode reinerpretAsFloat() {
		return new SimNode(ctx, e, VexVariableType.getFltType(size()));
	}

	public Long getAnyVal() {
		try {
			if (this.e.isNumeral()) {
				return ((BitVecNum) e).getLong();
			} else {
				Solver solver = ctx.mkSolver();
				if (solver.check() == Status.SATISFIABLE) {
					Model model = solver.getModel();
					Expr exp = model.eval(e, true);
					return ((BitVecNum) exp).getLong();
				} else {
					logger.error("Failed to concretize:" + this.e);
					return null;
				}
			}
		} catch (Exception e) {
			logger.error("Failed to concretize:" + this.e, e);
			return null;
		}
	}

}