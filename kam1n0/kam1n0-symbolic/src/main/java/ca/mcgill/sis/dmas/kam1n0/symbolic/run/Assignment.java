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

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.symbolic.Symbol;

public class Assignment {
	public Assignment(Symbol sym, String val) {
		this.sym = sym;
		this.value = val;
	}

	@Override
	public String toString() {
		return sym.toString() + " <- " + value;
	}

	public Symbol sym;
	public String value;
	public String err = StringResources.STR_EMPTY;

	public Assignment copy() {
		Assignment newAssign = new Assignment(this.sym, value);
		return newAssign;
	}
}