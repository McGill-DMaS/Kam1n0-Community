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

import ca.mcgill.sis.dmas.kam1n0.symbolic.SymbolicCCalls;
import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class Kam1n0SymbolicModule {

	public static void setup() {
		VexEnumeration.activate();
		VexOperationUtils.init(Kam1n0SymbolicModule.class.getClassLoader().getResourceAsStream("maps.json"));
		SymbolicCCalls.load(Kam1n0SymbolicModule.class.getClassLoader().getResourceAsStream("maps.ccall.json"));
		KamResourceLoader.loadLibrary("VEXIRBB");
		KamResourceLoader.loadLibrary("libz3");
	}

}
