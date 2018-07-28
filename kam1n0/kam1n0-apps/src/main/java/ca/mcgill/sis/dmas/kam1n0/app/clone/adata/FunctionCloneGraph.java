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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;

public class FunctionCloneGraph {

	public ArrayList<FunctionNode> nodes = new ArrayList<>();
	public ArrayList<Link> links = new ArrayList<>();

	public static class FunctionNode {
		public String name;
		public String srcName;
		public String srcFileName;
		public int binaryGroupID;
		public String binaryGroupName;
		public String codes;
		public String ncodes;
		public String srcCodes;
		public ArrayList<Double[]> clones = new ArrayList<>();
	}

	public static class Link {
		public int source, target;
		public double value;
	}

}
