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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam;

import java.util.List;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;

public class FunctionFullCloneDetector extends FunctionCloneDetector {

	public Indexer<Function> indexer;

	public FunctionFullCloneDetector(AsmObjectFactory factory, Indexer<Function> indexer) {
		super(factory);
		this.indexer = indexer;
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN.join("detector=", this.getClass().getSimpleName(), "indexer=",
				indexer.params());
	}

	@Override
	protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binaries, LocalJobProgress progress)
			throws Exception {

		List<Function> funcs = binaries.stream().flatMap(bin -> bin.functions.stream()).collect(Collectors.toList());

		indexer.index(rid, funcs, progress);
	}

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threshold, int topK, boolean avoidSameBinary) throws Exception {
		return indexer.query(rid, function, threshold, topK).stream()//
				.filter(tp -> tp != null) //
				.map(tp -> new FunctionCloneEntry(tp._1, tp._2))//
				.filter(ent -> !avoidSameBinary || ent.binaryId != function.binaryId).collect(Collectors.toList());

	}

	@Override
	public void init() throws Exception {
		indexer.init();
	}

	@Override
	public void close() throws Exception {
		indexer.close();
	}

}
