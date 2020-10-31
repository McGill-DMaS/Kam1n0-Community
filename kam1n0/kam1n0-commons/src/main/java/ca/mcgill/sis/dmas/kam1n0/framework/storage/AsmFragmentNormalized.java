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
package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import java.util.Iterator;
import java.util.List;

public class AsmFragmentNormalized implements AsmFragment {

	public List<List<String>> asmLines;
	public List<List<Integer>> oprTypes;

	@Override
	public Iterator<List<String>> iterator() {
		return asmLines.iterator();
	}

	public AsmFragmentNormalized(List<List<String>> lines, List<List<Integer>> oprTypes) {
		this.asmLines = lines;
		this.oprTypes = oprTypes;
	}

	@Override
	public List<List<String>> getAsmLines() {
		return asmLines;
	}

	@Override
	public List<List<Integer>> getOprTypes() {
		return oprTypes;
	}
}
