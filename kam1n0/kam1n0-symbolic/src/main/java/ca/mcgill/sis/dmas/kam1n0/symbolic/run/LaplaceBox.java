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

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microsoft.z3.BitVecNum;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Model;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import ca.mcgill.sis.dmas.kam1n0.symbolic.SimNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.Symbol;

public class LaplaceBox {

	private static Logger logger = LoggerFactory.getLogger(LaplaceBox.class);

	public long defaultValueForInputIfNotSuplied = 0xa;

	public Context ctx;
	public Model model = null;

	public LaplaceBox(Context ctx) {
		this.ctx = ctx;
		Solver solver = ctx.mkSolver();
		if (solver.check() == Status.SATISFIABLE) {
			model = solver.getModel();
		}
	}

	public void dispose() {
		ctx.dispose();
	}

	public RunResult run(RunConfiguration conf) {
		String str = null;
		Symbol sym = conf.subtitute();
		Expr exp = model.eval(sym.sNode.e, true);
		if (exp instanceof BitVecNum) {
			BigInteger val = ((BitVecNum) exp).getBigInteger();
			str = val.toString(16);
			if (sym.cNode.isIP(conf.configurable.arch.type)) {
				if (str.equalsIgnoreCase(Long.toHexString(conf.configurable.nextBlkSeq))) {
					str = IDEN_NEXT;
				} else
					str = IDEN_SKIP;
			} else {
				str = Integer.toHexString(val.intValue());
			}
		} else
			str = IDEN_SKIP; //temporary fix (skipping unknown type)

		Assignment output = new Assignment(sym, str);
		RunResult result = new RunResult(conf.inputAssignments, output);
		conf.result = result;
		return conf.result;
	}

	public long run(Model checkedModel, SimNode toBeEvaluated) {
		Expr exp = checkedModel.eval(toBeEvaluated.e, true);
		if (exp instanceof BitVecNum) {
			long val = ((BitVecNum) exp).getBigInteger().longValue();
			return val;
		} else {
			System.out.println(exp);
			System.out.println(exp.getClass().getName());
			return -1;
		}
	}

	public long run(SimNode toBeEvaluated) {
		Expr exp = model.eval(toBeEvaluated.e, true);
		if (exp instanceof BitVecNum) {
			long val = ((BitVecNum) exp).getBigInteger().longValue();
			return val;
		} else {
			System.out.println(exp);
			System.out.println(exp.getClass().getName());
			return -1;
		}
	}

	public void run(List<RunConfiguration> confs) {
		confs.forEach(this::run);
	}

	public final static String IDEN_NEXT = "NXT";
	public final static String IDEN_SKIP = "SKIP";

	@Deprecated
	public void runConf1(List<RunConfiguration> confs, boolean normalizeRegIP) {
		// has to follow: substitute -> solver -> check -> model -> evaluate
		Solver solver = ctx.mkSolver();
		if (solver.check() == Status.SATISFIABLE) {
			Model model = solver.getModel();
			for (int i = 0; i < confs.size(); ++i) {
				RunConfiguration conf = confs.get(i);
				Symbol sym = conf.subtitute();
				Expr exp = model.eval(sym.sNode.e, true);
				String str = ((BitVecNum) exp).getBigInteger().toString(16);
				if (normalizeRegIP && sym.cNode.isIP(conf.configurable.arch.type)) {
					if (str.equalsIgnoreCase(Long.toHexString(conf.configurable.nextBlkSeq))) {
						str = IDEN_NEXT;
					} else
						str = IDEN_SKIP;
				}
				Assignment output = new Assignment(sym, str);
				RunResult result = new RunResult(conf.inputAssignments, output);
				conf.result = result;
			}
		} else {
			logger.error("Failed to concretize:" + solver.getReasonUnknown());
		}
	}

	@Deprecated
	public void runConf2(List<RunConfiguration> confs, boolean normalizeRegIP) {
		// has to follow: substitute -> solver -> check -> model -> evaluate
		List<Symbol> substitutes = confs.stream().map(RunConfiguration::subtitute).collect(Collectors.toList());
		Solver solver = ctx.mkSolver();
		if (solver.check() == Status.SATISFIABLE) {
			Model model = solver.getModel();
			for (int i = 0; i < confs.size(); ++i) {
				RunConfiguration conf = confs.get(i);
				Symbol sym = substitutes.get(i);
				Expr exp = model.eval(sym.sNode.e, true);
				String str = ((BitVecNum) exp).getBigInteger().toString(16);
				if (normalizeRegIP && sym.cNode.isIP(conf.configurable.arch.type)) {
					if (str.equalsIgnoreCase(Long.toHexString(conf.configurable.nextBlkSeq))) {
						str = IDEN_NEXT;
					} else
						str = IDEN_SKIP;
				}
				Assignment output = new Assignment(sym, str);
				RunResult result = new RunResult(conf.inputAssignments, output);
				conf.result = result;
			}
		} else {
			logger.error("Failed to concretize:" + solver.getReasonUnknown());
		}
	}

	public Solver getSolver() {
		return ctx.mkSolver();
	}

	public Optimize getOptimize() {
		return ctx.mkOptimize();
	}

}
