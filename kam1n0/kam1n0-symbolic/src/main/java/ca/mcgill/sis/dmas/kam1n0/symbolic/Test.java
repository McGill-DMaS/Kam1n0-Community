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

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FPRMExpr;
import com.microsoft.z3.Model;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;
import com.microsoft.z3.Version;
import com.microsoft.z3.Z3Exception;

import ca.mcgill.sis.dmas.kam1n0.vex.VexConstant;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexConstantType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.RoundingMode;

public class Test {

	private static Logger logger = LoggerFactory.getLogger(Test.class);

	public static void main(String[] args) {
		try {
			System.loadLibrary("libz3");
			System.loadLibrary("libz3java");
			com.microsoft.z3.Global.ToggleWarningMessages(true);

			System.out.print("Z3 Major Version: ");
			System.out.println(Version.getMajor());
			System.out.print("Z3 Full Version: ");
			System.out.println(Version.getString());
			System.out.print("Z3 Full Version String: ");
			System.out.println(Version.getString());

			HashMap<String, String> cfg = new HashMap<String, String>();
			cfg.put("model", "true");
			Context ctx = new Context(cfg);

			String str = "100";
			VexConstant constant = new VexConstant();
			constant.size = 64;
			constant.type = VexConstantType.Ico_F64;
			constant.value = str;

			SimNode v0 = new SimNode(ctx, constant.getVal(), constant.type.toVariableType());
			SimNode v1 = SimNode.val(ctx, 3.1415926, 64);
			SimNode rm = SimNode.val(ctx, 3, 32);
			FPRMExpr rm_t = rm.toRm();
			v1 = v1.toInt(64, true, rm);
			v1 = v1.toFloat(64);
			v1 = v1.fpSub(v0, rm);

			SimNode i0 = SimNode.val(ctx, 1, 1);
			SimNode i1 = i0.signExtend(32);

			SimNode a1 = SimNode.val(ctx, 200, 32);
			SimNode a2 = SimNode.val(ctx, 10, 32);
			SimNode a3 = a1.add(a2);
			SimNode a4 = a3.setValues(a1, 100);

			Solver sovler = ctx.mkSolver();
			sovler.check();
			Model model = sovler.getModel();
			eval(model, v1);
			eval(model, v0);
			eval(model, rm.toRm());
			eval(model, i1);

			Long neg1 = 100l;
			String hex = Long.toHexString(neg1);
			Long val = Long.parseUnsignedLong(hex, 16);
			System.out.println(val);

			eval(model, a3);
			eval(model, a4);
			eval(model, a3.setValues(a1, 100));

		} catch (Z3Exception e) {
			logger.error("TEST Failed.", e);
		}
	}

	static void eval(Model model, SimNode node) {
		if (node.isFloat()) {
			String str = model.eval(node.toRawFloat(), true).toString();
			print(str);
		} else {
			String str = model.eval(node.e, true).toString();
			System.out.println(str);
		}
	}

	static void eval(Model model, Expr node) {
		String str = model.eval(node, true).toString();
		System.out.println(str);
	}

	static Model check(Context ctx, BoolExpr f, Status sat) throws Exception {
		Solver s = ctx.mkSolver();
		s.add(f);
		if (s.check() != sat)
			throw new Exception("HERE");
		if (sat == Status.SATISFIABLE)
			return s.getModel();
		else
			return null;
	}

	static void print(String val) {
		String[] parts = val.split(" ");

		double d = Double.parseDouble(parts[0]);
		d = d * Math.pow(2, Double.parseDouble(parts[1]));
		System.out.println(d);
	}

}
