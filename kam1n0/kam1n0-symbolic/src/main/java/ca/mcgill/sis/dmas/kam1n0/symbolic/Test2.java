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
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.RoundingMode;

public class Test2 {

	private static Logger logger = LoggerFactory.getLogger(Test2.class);

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

			SimNode sn1 = SimNode.val(ctx, 0xfff0, 32);
			sn1 = sn1.extract(7, 0);

			Solver sovler = ctx.mkSolver();
			System.out.println(sovler.check());
			Model model = sovler.getModel();
			System.out.println(model.eval(sn1.e, true));

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
