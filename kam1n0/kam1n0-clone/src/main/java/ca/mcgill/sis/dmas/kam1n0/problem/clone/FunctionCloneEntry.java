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
package ca.mcgill.sis.dmas.kam1n0.problem.clone;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import scala.Tuple3;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class FunctionCloneEntry implements Serializable, Comparable<FunctionCloneEntry> {

	private static final long serialVersionUID = -5272570009050217555L;

	/**
	 * Only for web detector
	 */
	public long functionId;
	public String functionName = StringResources.STR_EMPTY;
	public long binaryId;
	public String binaryName = StringResources.STR_EMPTY;
	public double similarity = Double.MAX_VALUE;
	public long codeSize;
	public long startingEA;

	/**
	 * This field is only used for detectors that support subgraph detection
	 */
	public List<HashSet<Tuple3<Long, Long, Double>>> clonedParts = new ArrayList<>();

	public FunctionCloneEntry() {
	}

	public FunctionCloneEntry(Function function, double similarity) {
		this.binaryId = function.binaryId;
		this.binaryName = function.binaryName;
		this.functionId = function.functionId;
		this.functionName = function.functionName;
		this.similarity = similarity;
		this.codeSize = function.codeSize;
	}

	public FunctionCloneEntry(Block aBlk, double similarity) {
		this.binaryId = aBlk.binaryId;
		this.binaryName = aBlk.binaryName;
		this.functionId = aBlk.functionId;
		this.functionName = aBlk.functionName;
		this.similarity = similarity;
		this.codeSize = aBlk.funcCodeSize;
	}

	@Override
	public String toString() {
		return functionName + "@" + binaryName + " -> " + StringResources.FORMAT_2R3D.format(similarity) + " -> "
				+ clonedParts.toString();
	};

	@Override
	public int compareTo(FunctionCloneEntry o) {
		return Double.compare(similarity, o.similarity);
	}

	// test
	public static void main(String[] args) {

	}

}
