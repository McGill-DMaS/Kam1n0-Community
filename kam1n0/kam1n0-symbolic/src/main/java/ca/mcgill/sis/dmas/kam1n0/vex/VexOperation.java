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

import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;

public class VexOperation {

	public VexOperationType tag;

	public static VexOperation createOperation(int typeIndex) {
		VexOperationType type = VexEnumeration.retrieveType(typeIndex, VexOperationType.class);
		VexOperation opr = new VexOperation();
		opr.tag = type;
		return opr;
	};

	public static VexOperation createOperation(VexOperationType tag) {
		VexOperation opr = new VexOperation();
		opr.tag = tag;
		return opr;
	};

	public String toStr() {
		return tag.toString().replaceAll("Iop_", "");
	}

}
