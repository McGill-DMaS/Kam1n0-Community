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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Iterables;
import com.google.common.collect.Table;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.io.collection.heap.DuplicatedRanker;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep.GeneralVectorIndex;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.FuncTokenized;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;
import scala.Tuple2;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew;

public class Asm2VecCloneDetectorIntegration extends FunctionCloneDetector implements Serializable {

	private static Logger logger = LoggerFactory.getLogger(Asm2VecCloneDetectorIntegration.class);

	private static final long serialVersionUID = 9037582236777128453L;

	public boolean useLsh = false;
	public transient GeneralVectorIndex index;

	public static Asm2VecCloneDetectorIntegration getDefaultDetector(AsmObjectFactory factory) {
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

	public static Asm2VecCloneDetectorIntegration getDefaultDetector(Asm2VecNewParam param, AsmObjectFactory factory) {
		if (MathUtilities.expTable == null)
			MathUtilities.createExpTable();
		Asm2VecCloneDetectorIntegration detector = new Asm2VecCloneDetectorIntegration(factory, param);
		return detector;
	}

	public Table<Long, Long, double[]> embds = HashBasedTable.create();
	public LearnerAsm2VecNew asm2vec = null;
	public Asm2VecNewParam param;
	public boolean trained = false;

	public Asm2VecCloneDetectorIntegration(AsmObjectFactory factory, Asm2VecNewParam param) {
		super(factory);
		this.param = param;
	}

	private boolean isExtern(Function func) {
		return func.blocks.get(0).codes.get(0).get(1).trim().equalsIgnoreCase("extrn");
	}

	public Asm2VecCloneDetectorIntegration() {
		super(null);
	}

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long appId, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {

		FuncTokenized func_t = new FuncTokenized(function);

		double[] pvec = asm2vec.infer(Arrays.asList(func_t)).values().iterator().next();

		DuplicatedRanker<Long> results = new DuplicatedRanker<>(topK);
		// Heap<String> results = new Heap<>(topK);
		if (this.index == null || !this.useLsh) {
			if (this.embds.containsRow(appId))
				this.embds.row(appId).forEach((id, vec2) -> {
					// if (avoidSameBinary) {
					// Function repFunc = factory.obj_functions.querySingle(appId, id);
					// if (repFunc.binaryId == function.binaryId)
					// return;
					// if (repFunc.blocks.get(0).peerSize < 3 && function.blocks.get(0).peerSize >
					// 10)
					// return;
					// if (this.isExtern(repFunc) && !this.isExtern(function))
					// return;
					// }
					double sim = MathUtilities.dot(pvec, vec2);
					//sim = Math.floor(sim * 1000) / 1000d;
					results.push(sim, id);
				});
		} else {
			this.index.query(appId, pvec, topK, function.functionId).forEach(tp2 -> {
				results.push(tp2._2(), tp2._1());
			});

		}

		return results.stream().parallel().filter(ent -> ent.getKey() > threadshold).map(
				ent -> new FunctionCloneEntry(factory.obj_functions.querySingle(appId, ent.getValue()), ent.getKey()))
				.filter(ent -> !avoidSameBinary || ent.binaryId != function.binaryId).collect(Collectors.toList());
	}

	@Override
	protected void indexFuncsToBeImplByChildren(long appId, List<Binary> binaries, LocalJobProgress progress)
			throws Exception {
		throw new UnsupportedOperationException(
				"The parent high level methods has been overrided by this class. Shouldn't reach this method.");
	}

	@Override
	public void index(long rid, Iterable<? extends BinaryMultiParts> binaries, LocalJobProgress progress)
			throws Exception {

		StageInfo stage_root = progress.nextStage(Asm2VecCloneDetectorIntegration.class, "Indexing...");
		Iterable<? extends BinaryMultiParts> oldBinaries = factory.browseBinary(rid);
		// counting the multiparts extracted from binarySurrogateMultipart does not
		// really load them into memory.
		// just counting the number of files.
		long totalParts = Iterables.size(binaries) + factory.obj_binaries.count(rid);
		binaries = Iterables.concat(binaries, oldBinaries);

		stage_root.progress = 0.2;
		StageInfo stage = progress.nextStage(Asm2VecCloneDetectorIntegration.class, "Storing assembly objects...");
		Iterable<Binary> bins = Iterables.concat(binaries);
		// will skip if functions existed.
		long count = 0;
		for (Binary bin : bins) {
			this.factory.addBinary(rid, bin);
			count++;
			stage.progress = count * 1.0 / totalParts;
		}
		stage.complete();
		stage_root.progress = 0.4;

		stage = progress.nextStage(Asm2VecCloneDetectorIntegration.class, "Start training data with lazy convert...");
		param.optm_parallelism = 10;
		// param.optm_iteration = 20;
		asm2vec = new LearnerAsm2VecNew(param);
		asm2vec.debug = false;
		asm2vec.stage = stage;

		Iterable<FuncTokenized> funcList = FuncTokenized.convert(binaries, -1);
		asm2vec.train(funcList);

		stage.complete();
		stage = progress.nextStage(Asm2VecCloneDetectorIntegration.class, "Producing embeddings...");
		Map<Long, double[]> vecs = asm2vec.produceNormalizedDocEmbdCpy().entrySet().stream()
				.collect(Collectors.toMap(ent -> Long.parseLong(ent.getKey()), ent -> ent.getValue()));
		List<Tuple2<Long, double[]>> embd_vecs = vecs.entrySet().stream()
				.map(ent -> new Tuple2<>(ent.getKey(), ent.getValue())).collect(Collectors.toList());

		stage_root.progress = 0.6;
		stage.complete();
		stage = progress.nextStage(Asm2VecCloneDetectorIntegration.class, "Indexing embeddings...");

		if (this.index != null && this.useLsh) {
			index.clear(rid);
			// batched indexing; since writing a big bucket will cause write timeout and
			// inefficient;
			// lets play safe.

			int batch_size = 5000;
			double total = Math.ceil(embd_vecs.size() * 1.0 / batch_size);
			for (int i = 0; i < total; ++i) {
				index.index(rid, progress, embd_vecs.subList(i,
						(i + 1) * batch_size > embd_vecs.size() ? embd_vecs.size() : (i + 1) * batch_size));
				stage.progress = (i + 1) / total;
			}
			this.embds.clear();
		} else {
			this.embds.rowKeySet().remove(rid);
			vecs.entrySet().stream().forEach(ent -> embds.put(rid, ent.getKey(), ent.getValue()));
		}
		stage.complete();
		stage_root.progress = 0.8;

		stage = progress.nextStage(Asm2VecCloneDetectorIntegration.class, "Saving models....");

		asm2vec.trainDocMap.clear();
		if (saveFunc != null)
			saveFunc.accept(rid, this);
		// meta.modelFactory.dump();

		stage.complete();

		stage_root.complete();
		trained = true;
	}

	@Override
	public String params() {
		return this.param.toCSV();
	}

	/**
	 * For storing itself after training.
	 */
	private transient BiConsumer<Long, Asm2VecCloneDetectorIntegration> saveFunc;

	@Override
	public void init() throws Exception {

	}

	public void customized_init(BiConsumer<Long, Asm2VecCloneDetectorIntegration> saveFunc, GeneralVectorIndex indx,
			AsmObjectFactory factory) {
		this.saveFunc = saveFunc;
		this.index = indx;
		this.factory = factory;
	}

	@Override
	public void close() throws Exception {
	}

	@Override
	public void clear(long rid) {
		index.clear(rid);
		factory.clear(rid);
	}
}
