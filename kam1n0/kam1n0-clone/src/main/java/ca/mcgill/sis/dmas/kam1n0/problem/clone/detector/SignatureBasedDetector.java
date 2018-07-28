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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectorForCLI;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.LuceneEngine;

public abstract class SignatureBasedDetector extends FunctionCloneDetector {

	private static Logger logger = LoggerFactory.getLogger(FunctionCloneDetectorForCLI.class);

	int r = 10;
	protected SignatureGenerator gen;
	LuceneEngine engine;

	public SignatureBasedDetector(AsmObjectFactory factory, SignatureGenerator generator) {
		super(factory);
		this.gen = generator;
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("r", r, gen.params());
	}

	@Override
	public void indexFuncsToBeImplByChildren(long rid, List<Binary> binary, LocalJobProgress progress)
			throws Exception {
		Counter counter = new Counter();
		engine.openWriter();
		StageInfo stage = progress.nextStage(this.getClass(), "Indexing functions");
		List<Function> funcs = binary.stream().flatMap(bin -> bin.functions.stream()).collect(Collectors.toList());
		funcs.stream().parallel().forEach(func -> {
			counter.inc();
			stage.progress = counter.getVal() / funcs.size();
			try {
				engine.index(func, gen.generateSignature(func));
			} catch (Exception e) {
				logger.error("Failed to index the given function.", e);
			}
		});
		stage.complete();
		engine.closeWriter();
	}

	@Override
	public List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {
		ArrayList<EntryPair<Long, Double>> rest = new ArrayList<>();
		engine.openReader();
		rest = engine.query(gen.generateSignatureForQuery(function), topK);
		return rest.stream().map(pair -> {
			Function srcFunc = this.factory.obj_functions.querySingle(rid, pair.key);
			if (avoidSameBinary && srcFunc.binaryId == function.binaryId)
				return null;
			return new FunctionCloneEntry(srcFunc, pair.value);
		}).filter(fce -> fce != null).collect(Collectors.toList());
	}

	@Override
	public void init() throws Exception {
		if (engine == null)
			engine = new LuceneEngine(r);
	}

	@Override
	public void close() throws Exception {
		engine.closeReader();
		engine.closeWriter();
		engine = null;
	}

}
