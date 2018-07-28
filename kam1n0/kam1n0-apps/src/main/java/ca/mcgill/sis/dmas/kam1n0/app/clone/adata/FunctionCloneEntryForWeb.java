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
package ca.mcgill.sis.dmas.kam1n0.app.clone.adata;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;

public class FunctionCloneEntryForWeb implements Serializable {

	private static final long serialVersionUID = 2045513072037628913L;

	public String functionId;
	public String functionName = StringResources.STR_EMPTY;
	public String binaryId;
	public String binaryName = StringResources.STR_EMPTY;
	public int numBbs = 0;
	public double similarity = -1;
	public FunctionDataUnit actualFunc = null;

	public ArrayList<ArrayList<Tupe>> clonedParts;

	public static class Tupe {
		public String _1 = StringResources.STR_EMPTY;
		public String _2 = StringResources.STR_EMPTY;

		public Tupe() {
		}

		public Tupe(String _1, String _2) {
			this._1 = _1;
			this._2 = _2;
		}
	}

	public FunctionCloneEntryForWeb(FunctionCloneEntry entry) {
		this.functionId = Long.toString(entry.functionId);
		this.functionName = entry.functionName;
		this.binaryId = Long.toString(entry.binaryId);
		this.binaryName = entry.binaryName;
		this.similarity = entry.similarity;
		this.numBbs = (int) entry.numBbs;

		clonedParts = entry.clonedParts.stream() //
				.map(set -> set//
						.stream() //
						.map(tp -> new Tupe(Long.toString(tp._1()), Long.toString(tp._2())))//
						.collect(Collectors.toCollection(ArrayList::new)))
				.collect(Collectors.toCollection(ArrayList::new));

	}

	public FunctionCloneEntryForWeb(FunctionDataUnit func, double similarity, int numbbs) {
		this.actualFunc = func;
		this.similarity = similarity;

		this.functionId = func.functionId;
		this.functionName = func.functionName;
		this.binaryId = func.binaryId;
		this.binaryName = func.binaryName;

		this.numBbs = numbbs;

	}

	public FunctionCloneEntryForWeb() {
	}

}
