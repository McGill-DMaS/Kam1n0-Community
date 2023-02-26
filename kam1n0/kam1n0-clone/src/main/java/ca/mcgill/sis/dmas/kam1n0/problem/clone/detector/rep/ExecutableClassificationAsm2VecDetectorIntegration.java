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

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Optional;
import java.util.Set;
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
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;

import java.time.Duration;
import java.time.Instant;

public class ExecutableClassificationAsm2VecDetectorIntegration extends FunctionCloneDetector implements Serializable {

	private static Logger logger = LoggerFactory.getLogger(ExecutableClassificationAsm2VecDetectorIntegration.class);

	private static final long serialVersionUID = 9037582236777128453L;


	public boolean useLsh = false;
	public transient GeneralVectorIndex index;

	public static ExecutableClassificationAsm2VecDetectorIntegration getDefaultDetector(AsmObjectFactory factory) {
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

	public static ExecutableClassificationAsm2VecDetectorIntegration getDefaultDetector(Asm2VecNewParam param, AsmObjectFactory factory) {
		if (MathUtilities.expTable == null)
			MathUtilities.createExpTable();
		ExecutableClassificationAsm2VecDetectorIntegration detector = new ExecutableClassificationAsm2VecDetectorIntegration(factory, param);
		return detector;
	}

	public Table<Long, Long, double[]> embds = HashBasedTable.create();
	public LearnerAsm2VecNew asm2vec = null;
	public Asm2VecNewParam param;
	public boolean trained = false;

	public HashMap<Long, Boolean> funInCluster;

	public ExecutableClassificationAsm2VecDetectorIntegration(AsmObjectFactory factory, Asm2VecNewParam param) {
		super(factory);
		this.param = param;
	}

	private boolean isExtern(Function func) {
		return func.blocks.get(0).codes.get(0).get(1).trim().equalsIgnoreCase("extrn");
	}

	public ExecutableClassificationAsm2VecDetectorIntegration() {
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
			if (this.embds.containsRow(appId)) {
				this.embds.row(appId).forEach((id, vec2) -> {
					if (!funInCluster.containsKey(id)) {
						return;
					}
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
					sim = Math.floor(sim * 1000) / 1000d;
					results.push(sim, id);
				});
			}
		} else {
			this.index.query(appId, pvec, topK, function.functionId).forEach(tp2 -> {
				results.push(tp2._2(), tp2._1());
			});

		}

		return results.stream().parallel().filter(ent -> ent.getKey() > threadshold)
				.map(ent -> new FunctionCloneEntry(factory.obj_functions.querySingle(appId, ent.getValue()),
						ent.getKey()))
				.filter(ent -> !avoidSameBinary || ent.binaryId != function.binaryId)
				.collect(Collectors.toList());
	}

	protected List<FunctionCloneEntry> detectClonesForClusterFuncToBeImpleByChildren(long appId, Function function,
																					 double threadshold, int topK) throws Exception {

		//use this thredshold not the real one

		FuncTokenized func_t = new FuncTokenized(function);

		double[] pvec = asm2vec.infer(Arrays.asList(func_t)).values().iterator().next();

		DuplicatedRanker<Long> results = new DuplicatedRanker<>(topK);
		// Heap<String> results = new Heap<>(topK);
		if (this.index == null || !this.useLsh) {
			if (this.embds.containsRow(appId))
				this.embds.row(appId).forEach((id, vec2) -> {
					if (!funInCluster.containsKey(id)) {
						return;
					}
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
					sim = Math.floor(sim * 1000) / 1000d;
					results.push(sim, id);
				});
		} else {
			this.index.query(appId, pvec, topK, function.functionId).forEach(tp2 -> {
				results.push(tp2._2(), tp2._1());
			});

		}

		return results.stream().parallel().filter(ent -> ent.getKey() > threadshold)
				.map(ent -> new FunctionCloneEntry(factory.obj_functions.querySingle(appId, ent.getValue()),
						ent.getKey()))
				.collect(Collectors.toList());
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

		Iterable<? extends BinaryMultiParts> oldBinaries = factory.browseBinary(rid);
		// counting the multiparts extracted from binarySurrogateMultipart does not
		// really load them into memory.
		// just counting the number of files.
		long totalParts = Iterables.size(binaries) + factory.obj_binaries.count(rid);
		binaries = Iterables.concat(binaries, oldBinaries);

		StageInfo stage_root = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Indexing...");
		stage_root.progress = 0.2;
		StageInfo stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Storing assembly objects...");
		Iterable<Binary> bins = Iterables.concat(binaries);
		// will skip if functions existed.
		long count = 0;
		//still separated tmp json files for new ones they will be combined by addBinary
		for (Binary bin : bins) {
			this.factory.addBinary(rid, bin);
			count++;
			stage.progress = count * 1.0 / totalParts;
		}
		stage.complete();
		stage_root.progress = 0.4;

		stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Start training data with lazy convert...");
		param.optm_parallelism = 10;
		param.optm_iteration = 20;
		Iterable<FuncTokenized> funcList = FuncTokenized.convert(binaries, -1);
		if (asm2vec == null) {
			asm2vec = new LearnerAsm2VecNew(param);
			asm2vec.debug = false;
			asm2vec.stage = stage;
			asm2vec.train(funcList);
		} else {
			asm2vec.cont_train(funcList);
		}


		stage.complete();
		stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Producing embeddings...");
		Map<Long, double[]> vecs = asm2vec.produceNormalizedDocEmbdCpy().entrySet().stream()
				.collect(Collectors.toMap(ent -> Long.parseLong(ent.getKey()), ent -> ent.getValue()));
		List<Tuple2<Long, double[]>> embd_vecs = vecs.entrySet().stream()
				.map(ent -> new Tuple2<>(ent.getKey(), ent.getValue())).collect(Collectors.toList());

		stage_root.progress = 0.6;
		stage.complete();
		stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Indexing embeddings...");

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

		stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Saving models....");

		asm2vec.trainDocMap.clear();
		saveFunc.accept(rid, this);
		// meta.modelFactory.dump();

		stage.complete();


		stage_root.complete();
		trained = true;
	}

	public void index(long rid, Iterable<? extends BinaryMultiParts> binaries, LocalJobProgress progress, boolean trainOrNot)
			throws Exception {

		Iterable<? extends BinaryMultiParts> oldBinaries = factory.browseBinary(rid);
		// counting the multiparts extracted from binarySurrogateMultipart does not
		// really load them into memory.
		// just count the number of files.

		if (binaries.iterator().hasNext() && !trainOrNot) {
			trained = false;
		}

		long totalParts = Iterables.size(binaries);
		//long totalParts = Iterables.size(binaries) + factory.obj_binaries.count(rid);
		//binaries = Iterables.concat(binaries, oldBinaries);

		StageInfo stage_root = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Indexing...");
		stage_root.progress = 0.2;
		StageInfo stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Storing assembly objects...");
		Iterable<Binary> bins = Iterables.concat(binaries);
		List<BinaryMultiParts> newbinaries = new ArrayList<BinaryMultiParts>();
		// will skip if functions existed.
		long count = 0;
		//still separated tmp json files for new ones they will be combined by addBinary
		for (Binary bin : bins) {
			if (bin == null)
				continue;
			this.factory.addBinary(rid, bin);
			count++;
			stage.progress = count * 1.0 / totalParts;
		}
		stage.complete();
		if (trainOrNot) {
			totalParts = Iterables.size(binaries) + factory.obj_binaries.count(rid);
			binaries = Iterables.concat(binaries, oldBinaries);
			int count_add = 0;
			for (BinaryMultiParts bin : binaries) {
				count_add++;
				newbinaries.add(bin);
				//logger.info("count add number:"+Integer.toString(count_add));
			}
			//logger.info("count add finished");

			//binaries.forEach(e->{newbinaries.add(e);});
			stage_root.progress = 0.4;

			stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Start training data with lazy convert...");
			param.optm_parallelism = 12;
			param.optm_iteration = 20;
			Iterable<FuncTokenized> funcList = FuncTokenized.convert(newbinaries, -1);
			asm2vec = new LearnerAsm2VecNew(param);
			asm2vec.debug = false;
			asm2vec.stage = stage;
			asm2vec.train(funcList);

			stage.complete();
			stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Producing embeddings...");
			Map<Long, double[]> vecs = asm2vec.produceNormalizedDocEmbdCpy().entrySet().stream()
					.collect(Collectors.toMap(ent -> Long.parseLong(ent.getKey()), ent -> ent.getValue()));
			List<Tuple2<Long, double[]>> embd_vecs = vecs.entrySet().stream()
					.map(ent -> new Tuple2<>(ent.getKey(), ent.getValue())).collect(Collectors.toList());

			stage_root.progress = 0.6;
			stage.complete();
			stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Indexing embeddings...");

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

			stage = progress.nextStage(ExecutableClassificationAsm2VecDetectorIntegration.class, "Saving models....");

			asm2vec.trainDocMap.clear();
			// meta.modelFactory.dump();

			stage.complete();
			stage_root.complete();
			trained = true;

		} else {
			stage_root.complete();
		}

		logger.info("Training complete");

		saveFunc.accept(rid, this);

	}


	@Override
	public String params() {
		return this.param.toCSV();
	}

	public double[] get_lsh(int n_dim,Random r)
	{
		double[] lsh = new double[n_dim];
		for(int i = 0; i<n_dim;i++)
		{
			lsh[i] = r.nextGaussian();
		}
		return lsh;
	}

	public ArrayList<Cluster> cluster(long appId, double similarity_threshold, double distribution_threshold, ArrayList<String> classes, Map<Long, Map<String, Double>> functionClassDist, Map<Long, String> functionIDtoName, Map<Long, Long> functionIDtobinID, Map<String, Float> classNBinary, int klsh, int llsh, int maxiFunc, boolean useLSH, StageInfo stage) {
		funInCluster = new HashMap<Long, Boolean>();
		ArrayList<Cluster> clusters = new ArrayList<Cluster>();
		//Map<String, Float> classNFunc = new HashMap<String, Float>();
		Map<String, Integer> classNCluster = new HashMap<String, Integer>();
		for (String cls : classes) {
			//classNFunc.put(cls, 0.0f);
			classNCluster.put(cls, 1);
		}
		Map<Long, double[]> vecs = new HashMap<Long, double[]>();
		ArrayList<Long> funcList = new ArrayList<Long>();
		UnionSet unionSet = new UnionSet();
		int n_dim = param.vec_dim;
		this.embds.row(appId).forEach((id, vec2) -> {
			vecs.put(id, vec2);
			funcList.add(id);
		});
		funcList.stream().forEach(ent ->
		{
			unionSet.set(ent, ent);
			//classNFunc.compute(functionIDtoClass.get(ent), (k,v)->v+1);
		});


		if (useLSH) {
			Random r = new Random();
			int n_fun = funcList.size();
			List<List<Long>> buckets = new ArrayList<List<Long>>();

			for(int i= 0; i<llsh; i++)
			{
				List<double[]> lshs = new ArrayList<double[]>();
				Map<String, List<Long>> tmpBuckets = new HashMap<String, List<Long>>();

				double[] lsh = MathUtilities.normalize(get_lsh(n_dim,r));
				lshs.add(lsh);
				String completeValues;
				for (int j = 0; j < n_fun; j++) {

					completeValues="";
					long func_id = funcList.get(j);
					double sim = MathUtilities.dot(lsh, MathUtilities.normalize(vecs.get(func_id)));
					String tmp;
					if(sim>0)
					{
						tmp = "1";
					}
					else {
						tmp = "0";
					}
					completeValues = completeValues+tmp;
					if(tmpBuckets.containsKey(completeValues))
					{
						tmpBuckets.get(completeValues).add(func_id);
					}
					else{
						List<Long> lis = new ArrayList<Long>();
						lis.add(func_id);
						tmpBuckets.put(completeValues,lis);
					}
				}
				List<String> toremove = new ArrayList<>();
				for (Map.Entry<String, List<Long>> entry : tmpBuckets.entrySet()) {
					List<Long> cur = entry.getValue();
					if(cur.size()<=maxiFunc)
					{
						toremove.add(entry.getKey());
						buckets.add(cur);
					}
				}
				for(String key: toremove)
				{
					tmpBuckets.remove(key);
				}

				Map<String, List<Long>> newBuckets;
				while(tmpBuckets.size() != 0)
				{
					newBuckets = new HashMap<String, List<Long>>();
					lsh = MathUtilities.normalize(get_lsh(n_dim,r));
					for (Map.Entry<String, List<Long>> entry : tmpBuckets.entrySet()) {
						String curkey = entry.getKey();
						String newkey;
						List<Long> cur = entry.getValue();
						for(long func: cur)
						{
							double sim = MathUtilities.dot(lsh, MathUtilities.normalize(vecs.get(func)));
							String tmp;
							if(sim>0)
							{
								tmp = "1";
							}
							else {
								tmp = "0";
							}
							newkey = curkey+tmp;
							if(newBuckets.containsKey(newkey))
							{
								newBuckets.get(newkey).add(func);

							}else{
								List<Long> lis = new ArrayList<Long>();
								lis.add(func);
								newBuckets.put(newkey,lis);
							}
						}
					}

					toremove = new ArrayList<>();
					for (Map.Entry<String, List<Long>> entry : newBuckets.entrySet()) {
						List<Long> cur = entry.getValue();
						String curkey = entry.getKey();
						if(cur.size()<=maxiFunc||curkey.length()>klsh)
						{
							toremove.add(entry.getKey());
							buckets.add(cur);
						}
					}
					for(String key: toremove)
					{
						newBuckets.remove(key);
					}
					tmpBuckets = newBuckets;
				}

			}


			int unioned = 0;
			int ununioned = 0;
			int done_buckets = 0;
			for(List<Long> bucket : buckets)
			{
				stage.progress = 0.9 * (done_buckets) / buckets.size();
				n_fun = bucket.size();
				for (int i = 0; i < n_fun; i++) {
					//logger.info("clustering:"+Double.toString(stage.progress));
					for (int j = i + 1; j < n_fun; j++) {
						//Instant start1 = Instant.now();
						double sim = MathUtilities.dot(MathUtilities.normalize(vecs.get(bucket.get(i))), MathUtilities.normalize(vecs.get(bucket.get(j))));
						if (sim > similarity_threshold) {

							unioned += 1;
							unionSet.union(bucket.get(i), bucket.get(j));
						} else
							ununioned += 1;
					}
				}
			}
			logger.info("number of functions:" + Integer.toString(funcList.size()));
			logger.info("number of clusters:" + Integer.toString(unionSet.count()));
			logger.info("unioned:" + Integer.toString(unioned) + " ununioned:" + Integer.toString(ununioned));



		} else {
			int unioned = 0;
			int ununioned = 0;
			int n_fun = funcList.size();
			for (int i = 0; i < n_fun; i++) {
				stage.progress = 0.9 * (i) / n_fun;
				//logger.info("clustering:"+Double.toString(stage.progress));
				for (int j = i + 1; j < funcList.size(); j++) {
					//Instant start1 = Instant.now();
					double sim = MathUtilities.dot(MathUtilities.normalize(vecs.get(funcList.get(i))), MathUtilities.normalize(vecs.get(funcList.get(j))));
					//Instant end1 = Instant.now();
					//Duration timeElapsed = Duration.between(start1, end1);
					//logger.info("Calculate sim Time taken: "+ timeElapsed.toMillis() +" milliseconds");
					//logger.info("sim:"+Double.toString(sim));
					if (sim > similarity_threshold) {

						//Instant start2 = Instant.now();
						unioned += 1;
						unionSet.union(funcList.get(i), funcList.get(j));
						//Instant end2 = Instant.now();
						//Duration timeElapsed2 = Duration.between(start2, end2);
						//logger.info("Union Time taken: "+ timeElapsed2.toMillis() +" milliseconds");
					} else
						ununioned += 1;
				}
			}
			logger.info("number of functions:" + Integer.toString(funcList.size()));
			logger.info("number of clusters:" + Integer.toString(unionSet.count()));
			logger.info("unioned:" + Integer.toString(unioned) + " ununioned:" + Integer.toString(ununioned));

		}



		Set<Long> unions = unionSet.getUnionSet();
		logger.info(Integer.toString(unions.size()));
		//try
		//{

		//PrintWriter out;
		//out = new PrintWriter("cls_dist.txt");
		for (long uni : unions) {

			//logger.info("----------------\n Union: "+Long.toString(uni)+"\n\n");
			Cluster cluster = new Cluster();
			for (String cls : classes) {
				cluster.classDist.put(cls, 0.0);
			}
			unionSet.functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(uni)).forEach(ent -> {
				cluster.addFunction(ent.getKey());
				logger.info(functionIDtoName.get(ent.getKey()) + "\n");
			});

			cluster.functionIDList.stream().forEach(ent -> {
				functionClassDist.get(ent).entrySet().stream().forEach(e -> {
					cluster.classDist.compute(e.getKey(), (k, v) -> v + e.getValue());
				});
			});
			//cluster.classDist.entrySet().stream().forEach(ent->{logger.info("First Time: "+ent.getKey()+" "+Double.toString(ent.getValue()));});
			cluster.classDist.entrySet().stream().forEach(ent -> {
				double normed = ent.getValue() / (classNBinary.get(ent.getKey()) + 0.000001);
				cluster.classDist.put(ent.getKey(), normed);
			});
			//cluster.classDist.entrySet().stream().forEach(ent->{logger.info("Second Time: "+ent.getKey()+" "+Double.toString(ent.getValue()));});
			double summ = cluster.classDist.entrySet().stream().map(ent -> ent.getValue()).reduce(0., Double::sum);
			cluster.classDist.entrySet().stream().forEach(ent -> {
				double normed = ent.getValue() / (summ + 0.000001f);
				cluster.classDist.put(ent.getKey(), normed);
			});
			//cluster.classDist.entrySet().stream().forEach(ent->{logger.info("Third Time: "+ent.getKey()+" "+Double.toString(ent.getValue()));});

			double mini = cluster.classDist.entrySet().stream().map(ent -> ent.getValue()).reduce(Double.MAX_VALUE, Double::min);
			double maxi = cluster.classDist.entrySet().stream().map(ent -> ent.getValue()).reduce(Double.MIN_VALUE, Double::max);
			//logger.info("Max: "+Double.toString(maxi)+" Min:"+Double.toString(mini));


			if ((maxi - mini > distribution_threshold)&&cluster.functionIDList.size()<1000) //if(clusterCls.isPresent()) if(maxi-mini > 0.3) maxi-mini > 0.05
			{
				//out.print("\n-------\n");
				//cluster.classDist.entrySet().stream().forEach(ent->{out.println(ent.getKey()+" "+Double.toString(ent.getValue())+"\n");});
				Optional<String> clusterCls2 = cluster.classDist.entrySet().stream().filter(ent -> ent.getValue() >= maxi - 1e-6).map(ent -> ent.getKey()).findFirst();
				cluster.className = clusterCls2.get();
				cluster.functionIDList = cluster.functionIDList.stream().collect(Collectors.toSet()); //filter(ent->functionIDtoClass.get(ent).equals(cluster.className)).
				cluster.functionIDList.stream().forEach(ent -> cluster.addBinary(functionIDtobinID.get(ent)));

				if (cluster.functionIDList.size() >= 2 && cluster.binaryIDList.size() >= 2) {
					cluster.functionIDList.stream().forEach(func -> funInCluster.put(func, true));
					cluster.clusterName = cluster.className + "_Cluster" + Integer.toString(classNCluster.get(cluster.className));
					//logger.info("A new cluster: "+cluster.clusterName+"\n---\n");
					classNCluster.compute(cluster.className, (k, v) -> v + 1);
					clusters.add(cluster);
				}
			    /*
			    else
			    {
			    	logger.info("Cluster Abondoned: n function in the cluster "+ Integer.toString(cluster.functionIDList.size())+ "n binaries: " + Integer.toString(cluster.binaryIDList.size()) + "\n---\n");
			    }
			    */
			}
			/*
		    else
		    {
		    	logger.info("Cluster Abondoned because of no significant class\n---\n");
		    }
		    */
		}


	    /*
	    	}
        catch (FileNotFoundException e1) {
        		// TODO Auto-generated catch block
        		e1.printStackTrace();
        	}
        */
		saveFunc.accept(appId, this);
		return clusters;
	}

	public ArrayList<Cluster> SLINKcluster(long appId, int n_exe_threshold, ArrayList<String> classes, Map<Long, String> functionIDtoClass, Map<Long, String> functionIDtoName, Map<Long, Long> functionIDtobinID, Map<String, Float> classNBinary, StageInfo stage) {
		funInCluster = new HashMap<Long, Boolean>();
		ArrayList<Cluster> clusters = new ArrayList<Cluster>();
		// Map<String, Float> classNFunc = new HashMap<String, Float>();
		Map<String, Integer> classNCluster = new HashMap<String, Integer>();

		PrintWriter out;

		for (String cls : classes) {
			//	classNFunc.put(cls, 0.0f);
			classNCluster.put(cls, 1);
		}
		Map<Long, double[]> vecs = new HashMap<Long, double[]>();
		ArrayList<Long> funcList = new ArrayList<Long>();
		this.embds.row(appId).forEach((id, vec2) -> {
			vecs.put(id, vec2);
			funcList.add(id);
		});


		PrintWriter out2;
		try {
			out2 = new PrintWriter("fun2cls.txt");
			for (Long k : vecs.keySet()) {
				out2.println(Long.toString(k) + " ");
				out2.println(Long.toString(k) + " " + functionIDtoName.get(k) + " ");
				out2.println(Long.toString(k) + " " + functionIDtoClass.get(k) + "\n");
			}
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		//funcList.stream().forEach(ent->
		//{
		//	classNFunc.compute(functionIDtoClass.get(ent), (k,v)->v+1);
		//});

		int N;
		int[] pi;
		float[] l;
		float[] mu;

		N = funcList.size();

		pi = new int[N];
		l = new float[N];
		mu = new float[N];


		//try {
		//	out = new PrintWriter("cluster_info.txt");
		pi[0] = 1;
		l[0] = Float.MAX_VALUE;

		for (int n = 0; n < N - 1; n++) {
			logger.info(Integer.toString(n) + "/" + Integer.toString(N - 1) + "=" + Float.toString((float) n / (N - 1)));
			stage.progress = (double) n / (N - 1);
			pi[n + 1] = n + 1;
			l[n + 1] = Float.MAX_VALUE;
			for (int i = 0; i <= n; i++) {
				mu[i] = 1 - (float) MathUtilities.dot(MathUtilities.normalize(vecs.get(funcList.get(i))), MathUtilities.normalize(vecs.get(funcList.get(n + 1))));

			}

			for (int i = 0; i <= n; i++) {
				if (l[i] >= mu[i]) {
					mu[pi[i]] = Math.min(mu[pi[i]], l[i]);
					l[i] = mu[i];
					pi[i] = n + 1;
				} else {
					mu[pi[i]] = Math.min(mu[pi[i]], mu[i]);
				}
			}

			for (int i = 0; i <= n; i++) {
				if (l[i] >= l[pi[i]])
					pi[i] = n + 1;
			}
		}

		ArrayList<Tuple> tuples = new ArrayList<Tuple>();

		UnionSetForSLink unionSet = new UnionSetForSLink();
		funcList.stream().forEach(ent ->
		{
			unionSet.set(ent, ent);
		});

		for (int n = 0; n < N - 1; n++) {
			tuples.add(new Tuple(n, pi[n], l[n]));
			//out.println("ln:"+Float.toString(l[n]));
			//logger.info("("+Integer.toString(n)+","+Integer.toString(pi[n])+","+Double.toString(l[n])+")\n");
		}
		Collections.sort(tuples, (o1, o2) -> o1.dis.compareTo(o2.dis));
		tuples.stream().forEach(e -> {
			//e.print(out, funcList, functionIDtoName);
			unionSet.union(funcList.get(e.node1), funcList.get(e.node2), functionIDtoClass, classNBinary);
			//unionSet.print_union(out, funcList.get(e.node1), functionIDtoName);
		});

		//out.close();


		Set<Long> unions = unionSet.getUnionSet();
		for (long uni : unions) {
			//logger.info("----------------\n Union: "+Long.toString(uni)+"\n\n");
			Cluster cluster = new Cluster();
			unionSet.functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(uni)).forEach(ent -> {
				cluster.addFunction(ent.getKey());
				logger.info(functionIDtoName.get(ent.getKey()) + "\n");
			});

			cluster.className = functionIDtoClass.get(cluster.functionIDList.iterator().next());
			cluster.functionIDList = cluster.functionIDList.stream().filter(ent -> functionIDtoClass.get(ent).equals(cluster.className)).collect(Collectors.toSet());
			cluster.functionIDList.stream().forEach(ent -> cluster.addBinary(functionIDtobinID.get(ent)));
			cluster.classDist.put(cluster.className, 1.0);

			if (cluster.binaryIDList.size() >= n_exe_threshold) //cluster.functionIDList.size()>=n_exe_threshold&&
			{
				cluster.functionIDList.stream().forEach(func -> funInCluster.put(func, true));
				cluster.clusterName = cluster.className + "_Cluster" + Integer.toString(classNCluster.get(cluster.className));
				//logger.info("A new cluster: "+cluster.clusterName+"\n---\n");
				classNCluster.put(cluster.className, classNCluster.get(cluster.className) + 1);
				clusters.add(cluster);
			}
			/*
			else
			{
				logger.info("Cluster Abondoned: n function in the cluster "+ Integer.toString(cluster.functionIDList.size())+ "n binaries: " + Integer.toString(cluster.binaryIDList.size()) + "\n---\n");
			}
			*/
		}
		saveFunc.accept(appId, this);
		/*} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}*/


		return clusters;
	}


	public static class Tuple {
		public int node1;
		public int node2;
		public Double dis;

		public Tuple(int node1, int node2, double dis) {
			super();
			this.node1 = node1;
			this.node2 = node2;
			this.dis = dis;
		}

		public void print(PrintWriter out, ArrayList<Long> funcList, Map<Long, String> functionIDtoName) {
			out.println("----------\n(" + Long.toString(this.node1) + "," + Long.toString(this.node2) + "," + Double.toString(this.dis) + ")\n");
			//out.println("----------\n("+functionIDtoName.get(funcList.get(this.node1))+","+functionIDtoName.get(funcList.get(this.node2))+","+Double.toString(this.dis)+")\n");
		}
	}


	public class UnionSet {
		public Map<Long, Long> functionToUnionMap;
		private int count;

		public UnionSet() {
			count = 0;
			functionToUnionMap = new HashMap<Long, Long>();
		}

		public int count() {
			return count;
		}

		public boolean connected(Long funtionp, Long functionq) {
			return find(funtionp).equals(find(functionq));
		}

		public Long find(Long p) {
			return functionToUnionMap.get(p);
		}

		public Long set(Long p, Long pID) {
			count++;
			return functionToUnionMap.put(p, pID);
		}

		public boolean union(Long functionp, Long functionq) {
			Long pID = find(functionp);
			Long qID = find(functionq);
			if (connected(functionp, functionq)) return false;

			ArrayList<Long> tmp = new ArrayList<Long>();
			functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(pID)).forEach(ent -> tmp.add(ent.getKey()));
			tmp.stream().forEach(ent -> {
				functionToUnionMap.put(ent, qID);
			});
			count--;
			return true;
		}

		public void print_union(PrintWriter out, Long functionp, Map<Long, String> functionIDtoName) {
			Long pID = find(functionp);
			long n = functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(pID)).count();
			out.print("--\n" + Long.toString(n) + "\n");
			out.print("--\n(");
			functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(pID)).forEach(ent -> out.print(functionIDtoName.get(ent.getKey()) + ", "));
			out.println(")\n");
		}

		public Set<Long> getUnionSet() {
			Set<Long> unionSet = new HashSet<Long>();
			functionToUnionMap.entrySet().stream().forEach(ent -> unionSet.add(ent.getValue()));
			return unionSet;
		}
	}

	public static class UnionSetForSLink {
		public Map<Long, Long> functionToUnionMap;
		public Map<Long, Boolean> unionOut;
		public int count;

		public UnionSetForSLink() {
			count = 0;
			functionToUnionMap = new HashMap<Long, Long>();
			unionOut = new HashMap<Long, Boolean>();
		}

		public int count() {
			return count;
		}

		public boolean connected(Long funtionp, Long functionq) {
			return find(funtionp).equals(find(functionq));
		}

		public Long find(Long p) {
			return functionToUnionMap.get(p);
		}

		public Long set(Long p, Long pID) {
			count++;
			return functionToUnionMap.put(p, pID);
		}

		public Boolean union(Long functionp, Long functionq, Map<Long, String> functionIDtoClass, Map<String, Float> classNBinary) {
			Long pID = functionToUnionMap.getOrDefault(functionp, -1L);
			Long qID = functionToUnionMap.getOrDefault(functionq, -1L);
			String classP = functionIDtoClass.get(pID);
			String classQ = functionIDtoClass.get(qID);
			if (pID == -1L || qID == -1L)
				return false;
			if (!classP.equals(classQ)) {
				unionOut.put(pID, true);
				unionOut.put(qID, true);
				return false;
			}
			if (unionOut.containsKey(pID)) {
				unionOut.put(qID, true);
				return false;
			}
			if (unionOut.containsKey(qID)) {
				unionOut.put(pID, true);
				return false;
			}
			ArrayList<Long> tmp = new ArrayList<Long>();
			functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(pID)).forEach(ent -> tmp.add(ent.getKey()));
			tmp.stream().forEach(ent -> {
				functionToUnionMap.put(ent, qID);
			});
			count--;
			Long n_func = functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(qID)).count();
			if (n_func >= classNBinary.get(classQ))
				unionOut.put(qID, true);
			return true;
		}

		public void print_union(PrintWriter out, Long functionp, Map<Long, String> functionIDtoName) {
			Long pID = find(functionp);
			long n = functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(pID)).count();
			out.print("--\n" + Long.toString(n) + "\n");
			out.print("--\n(");
			functionToUnionMap.entrySet().stream().filter(ent -> ent.getValue().equals(pID)).forEach(ent -> out.print(functionIDtoName.get(ent.getKey()) + ", "));
			out.println(")\n");
		}

		public Set<Long> getUnionSet() {
			Set<Long> unionSet = new HashSet<Long>();
			functionToUnionMap.entrySet().stream().forEach(ent -> unionSet.add(ent.getValue()));
			return unionSet;
		}
	}


	/**
	 * For storing itself after training.
	 */
	private transient BiConsumer<Long, ExecutableClassificationAsm2VecDetectorIntegration> saveFunc;

	@Override
	public void init() throws Exception {

	}

	public void customized_init(BiConsumer<Long, ExecutableClassificationAsm2VecDetectorIntegration> saveFunc, GeneralVectorIndex indx,
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
