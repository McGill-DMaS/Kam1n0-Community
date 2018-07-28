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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.io.collection.heap.DuplicatedRanker;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.FuncTokenized;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecEXP;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecEXP.Asm2VecNewParam;

public class Asm2VecCloneDetector extends FunctionCloneDetector implements Serializable {

	private static final long serialVersionUID = 9037582236777128453L;

	public static Asm2VecCloneDetector getDefaultDetector(AsmObjectFactory factory) {
		Asm2VecNewParam param = new Asm2VecNewParam();
		param.optm_parallelism = 5;
		param.optm_iteration = 50;
		param.optm_window = 2;
		param.optm_negSample = 25;
		param.min_freq = 1;
		param.vec_dim = 50;
		param.optm_subsampling = -1;
		return getDefaultDetector(param, factory);
	}

	public static Asm2VecCloneDetector getDefaultDetector(Asm2VecNewParam param, AsmObjectFactory factory) {
		if (MathUtilities.expTable == null)
			MathUtilities.createExpTable();
		Asm2VecCloneDetector detector = new Asm2VecCloneDetector(factory, param);
		return detector;
	}

	private static Logger logger = LoggerFactory.getLogger(Asm2VecCloneDetector.class);

	private Map<String, double[]> embds = null;
	public LearnerAsm2VecEXP asm2vec = null;
	public Asm2VecNewParam param;
	public Consumer<Integer> hood = null;

	public Asm2VecCloneDetector(AsmObjectFactory factory, Asm2VecNewParam param) {
		super(factory);
		this.param = param;
	}

	private boolean isExtern(Function func) {
		return func.blocks.get(0).codes.get(0).get(1).trim().equalsIgnoreCase("extrn");
	}

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long appId, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {

		// FuncTokenized func_t = new FuncTokenized(function);
		double[] pvec = this.embds.get(Long.toString(function.functionId));
		// asm2vec.infer(Arrays.asList(func_t)).values().iterator().next();

		DuplicatedRanker<String> results = new DuplicatedRanker<>(topK);
		// Heap<String> results = new Heap<>(topK);
		this.embds.forEach((id, vec2) -> {
			if (avoidSameBinary) {
				Function repFunc = factory.obj_functions.querySingle(appId, Long.parseLong(id));
				if (repFunc.binaryId == function.binaryId)
					return;
				if (repFunc.blocks.get(0).peerSize < 3 && function.blocks.get(0).peerSize > 10)
					return;
				if (this.isExtern(repFunc) && !this.isExtern(function))
					return;
			}
			double sim = MathUtilities.dot(pvec, vec2);
			// sim = Math.floor(sim * 1000) / 1000d;
			results.push(sim, id);
		});

		return results.stream().parallel().filter(ent -> ent.getKey() > threadshold)
				.filter(ent -> !avoidSameBinary || Long.parseLong(ent.getValue()) != function.functionId)
				.map(ent -> new FunctionCloneEntry(
						factory.obj_functions.querySingle(appId, Long.parseLong(ent.getValue())), ent.getKey()))
				.collect(Collectors.toList());
	}

	public transient List<Binary> last_index;

	@Override
	public void index(long rid, Iterable<? extends BinaryMultiParts> binaries, LocalJobProgress progress)
			throws Exception {

		last_index = Lists.newArrayList(Iterables.concat(binaries));
		last_index.forEach(bin -> factory.addBinary(rid, bin));

		asm2vec = new LearnerAsm2VecEXP(param);
		asm2vec.debug = false;
		asm2vec.iterationHood = this.hood;

		// List<FuncTokenized> funcList = binaries.stream().flatMap(bin ->
		// bin.functions.stream())s
		// .map(func -> new FuncTokenized(func)).collect(Collectors.toList());

		List<FuncTokenized> funcList = FuncTokenized.convert(last_index, -1);

		Collections.shuffle(funcList);
		logger.info("Total {} documents", funcList.size());

		asm2vec.train(funcList);

		logger.info("Merging embds...");
		// Map<String, double[]> embd = asm2vec.produceNormalizedDocEmbdCpy();
		// this.embds = new HashMap<>();
		// for (FuncTokenized func : funcList) {
		// ArrayList<double[]> c_embd = func.calls.stream().distinct().map(id ->
		// embd.get(Long.toString(id)))
		// .filter(f -> f !=
		// null).collect(Collectors.toCollection(ArrayList::new));
		// double[] avg = MathUtilities.avg(c_embd, this.param.vec_dim);
		// double[] target = embd.get(func.id);
		// if (target != null) {
		// double[] n_vec = MathUtilities.concate(target, avg);
		// this.embds.put(func.id, n_vec);
		// }
		// }
		this.embds = asm2vec.produceNormalizedDocEmbdCpy();
	}

	@Override
	protected void indexFuncsToBeImplByChildren(long appId, List<Binary> binaries, LocalJobProgress progress)
			throws Exception {

		throw new UnsupportedOperationException();
	}

	@Override
	public String params() {
		return this.param.toCSV();
	}

	@Override
	public void init() throws Exception {

	}

	@Override
	public void close() throws Exception {

	}

}
