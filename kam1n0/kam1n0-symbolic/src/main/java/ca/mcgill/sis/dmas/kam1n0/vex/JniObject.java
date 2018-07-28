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

import java.lang.reflect.Constructor;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;

import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExBBPTR;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExBinder;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExBinop;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExCCall;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExConst;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExGet;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExGetI;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExITE;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExLoad;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExQop;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExRdTmp;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExTriop;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExUnop;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.ExVECRET;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmAbiHint;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmCAS;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmDirty;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmDirtyFxStat;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmExit;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmIMark;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmLLSC;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmLoadG;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmMBE;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmNoOp;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmPut;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmPutI;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmStore;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmStoreG;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmWrTmp;
import ca.mcgill.sis.dmas.kam1n0.vex.variable.IRRegArray;

public class JniObject {

	public static void printCConstructor(Class<?> c) {

		Constructor<?>[] allConstructors = c.getDeclaredConstructors();

		StringBuilder body = new StringBuilder();
		body.append("jobject create_" + c.getSimpleName().replace(".", "_") + "(JNIEnv * jenv, ");
		for (Constructor<?> ctor : allConstructors) {
			Parameter[] params = ctor.getParameters();
			for (int i = 0; i < params.length; i++) {
				Parameter param = params[i];
				Class<?> paramt = param.getType();
				if (paramt == int.class) {
					body.append("jint " + param.getName() + ", ");
				} else if (paramt == boolean.class) {
					body.append("jboolean " + param.getName() + ", ");
				} else if (paramt == long.class) {
					body.append("jlong " + param.getName() + ", ");
				} else if (paramt == byte.class) {
					body.append("jbyte " + param.getName() + ", ");
				} else if (paramt == char.class) {
					body.append("jchar " + param.getName() + ", ");
				} else if (paramt == short.class) {
					body.append("jshort " + param.getName() + ", ");
				} else if (paramt == float.class) {
					body.append("jfloat " + param.getName() + ", ");
				} else if (paramt == double.class) {
					body.append("jdouble " + param.getName() + ", ");
				} else {
					body.append("jobject " + param.getName() + "_" + paramt.getSimpleName() + ", ");
				}
			}
			break;
		}
		body.deleteCharAt(body.length() - 1);
		body.deleteCharAt(body.length() - 1);

		body.append(")").append(System.lineSeparator()).append("{").append(System.lineSeparator());
		body.append("   jclass target_class = (*jenv)->FindClass(jenv, \"").append(getObjectClassTypeName(c))
				.append("\");").append(System.lineSeparator());

		body.append("   jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class,  \"<init>\", \"(");

		for (Constructor<?> ctor : allConstructors) {
			Parameter[] params = ctor.getParameters();
			for (int i = 0; i < params.length; i++) {
				Parameter param = params[i];
				Class<?> paramt = param.getType();
				if (paramt == int.class) {
					body.append("I");
				} else if (paramt == boolean.class) {
					body.append("Z");
				} else if (paramt == long.class) {
					body.append("J");
				} else if (paramt == byte.class) {
					body.append("B");
				} else if (paramt == char.class) {
					body.append("C");
				} else if (paramt == short.class) {
					body.append("S");
				} else if (paramt == float.class) {
					body.append("F");
				} else if (paramt == double.class) {
					body.append("D");
				} else {
					body.append(getObjectClassTypeName(paramt));
				}
			}
			break;
		}
		body.append(")V\");").append(System.lineSeparator());

		body.append("   return (*jenv)->NewObject(jenv, target_class, constructor, ");
		for (Constructor<?> ctor : allConstructors) {
			Parameter[] params = ctor.getParameters();
			for (int i = 0; i < params.length; i++) {
				Parameter param = params[i];
				Class<?> paramt = param.getType();
				if (paramt == int.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == boolean.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == long.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == byte.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == char.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == short.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == float.class) {
					body.append(param.getName() + ", ");
				} else if (paramt == double.class) {
					body.append(param.getName() + ", ");
				} else {
					body.append(param.getName() + "_" + paramt.getSimpleName() + ", ");
				}

			}
			break;
		}
		body.deleteCharAt(body.length() - 1);
		body.deleteCharAt(body.length() - 1);
		body.append(");").append(System.lineSeparator()).append("}");

		System.out.println(body.toString());

	}

	public static String getObjectClassTypeName(Class<?> tclass) {
		return "L" + tclass.getCanonicalName().replace(".", "/") + ";";
	}

	public static void main(String[] args) {
		printCConstructor(VexCall.class);

		printCConstructor(ExBinder.class);
		printCConstructor(ExBinop.class);
		printCConstructor(ExCCall.class);
		printCConstructor(ExConst.class);
		printCConstructor(ExGet.class);
		printCConstructor(ExGetI.class);
		printCConstructor(ExLoad.class);
		printCConstructor(ExQop.class);
		printCConstructor(ExRdTmp.class);
		printCConstructor(ExTriop.class);
		printCConstructor(ExUnop.class);
		printCConstructor(ExITE.class);
		printCConstructor(ExVECRET.class);
		printCConstructor(ExBBPTR.class);

		printCConstructor(StmAbiHint.class);
		printCConstructor(StmCAS.class);
		printCConstructor(StmDirty.class);
		printCConstructor(StmDirtyFxStat.class);
		printCConstructor(StmExit.class);
		printCConstructor(StmIMark.class);
		printCConstructor(StmLLSC.class);
		printCConstructor(StmLoadG.class);
		printCConstructor(StmMBE.class);
		printCConstructor(StmNoOp.class);
		printCConstructor(StmPut.class);
		printCConstructor(StmPutI.class);
		printCConstructor(StmStore.class);
		printCConstructor(StmStoreG.class);
		printCConstructor(StmWrTmp.class);
		
		printCConstructor(IRRegArray.class);

		VexEnumeration.main(args);

	}

}
