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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;

public class PairewiseEnumerationDetector extends FunctionCloneDetector {

	public PairewiseEnumerationDetector(AsmObjectFactory factory, FunctionSurrogateComparator comparator) {
		super(factory);
		this.comparator = comparator;
	}

	protected FunctionSurrogateComparator comparator;

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {
		HashMap<EntryPair<Long, Long>, FunctionCloneEntry> tmpSet = new HashMap<>();
		factory.browseFunc().forEach(srcFunc -> {
			if (avoidSameBinary && srcFunc.binaryId == function.binaryId)
				return;
			double sc = comparator.compareTo(function, srcFunc);
			if (sc > threadshold) {
				EntryPair<Long, Long> key = new EntryPair<>(function.functionId, srcFunc.functionId);
				FunctionCloneEntry ent = tmpSet.get(key);
				if (ent == null) {
					ent = new FunctionCloneEntry(function, sc);
					tmpSet.put(key, ent);
				}
				if (ent.similarity < sc)
					ent.similarity = sc;
			}
		});
		return tmpSet.values().stream().collect(Collectors.toList());
	}

	@Override
	public String params() {
		return comparator.params();
	}

	@Override
	protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binary, LocalJobProgress progress)
			throws Exception {
		progress.nextStage(this.getClass(), "Indxing finished");
	}

	@Override
	public void init() throws Exception {

	}

	@Override
	public void close() throws Exception {

	}

}
