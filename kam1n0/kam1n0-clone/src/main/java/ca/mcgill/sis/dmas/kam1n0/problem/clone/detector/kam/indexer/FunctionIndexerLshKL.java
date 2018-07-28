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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.indexer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashMultimap;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.Bucket;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketIndex;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.FeatureVecFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.FeatureVec;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.vechash.SimHash;
import scala.Tuple2;
import scala.Tuple3;

public class FunctionIndexerLshKL extends Indexer<Function> {

	private static Logger logger = LoggerFactory.getLogger(FunctionIndexerLshKL.class);

	private List<HashSchema> schemas;
	private AsmObjectFactory objectFactory;
	private FeatureConstructor featureGenerator;

	private BucketIndex index;

	private int K;
	private int L;
	private HashSchemaTypes type;

	public FunctionIndexerLshKL(SparkInstance sparkInstance, AsmObjectFactory objectFactory, BucketIndex index,
			FeatureConstructor featureGenerator, int K, int L, HashSchemaTypes type) {
		super(sparkInstance);
		this.objectFactory = objectFactory;
		this.index = index;
		this.featureGenerator = featureGenerator;

		this.K = K;
		this.L = L;
		this.type = type;

		schemas = new ArrayList<>(L);
		Random rand = new Random(1234);
		for (int i = 0; i < L; ++i)
			schemas.add(HashSchema.getHashSchema(featureGenerator.featureElements, type, K, rand));
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("indexer=", this.getClass().getSimpleName(), "K=", K, "L=", L,
				"LshType=", type);
	}

	@Override
	public boolean index(long rid, List<Function> funcs, LocalJobProgress progress) {
		StageInfo stage = progress.nextStage(this.getClass(), "Computing feature vectors");
		List<Tuple2<Long, SparseVector>> vecs = funcs.stream()
				//
				.map(//
						func -> //
						new Tuple2<>(func.functionId, featureGenerator.score(func)))//
				.collect(Collectors.toList());
		stage.complete();

		stage = progress.nextStage(this.getClass(), "Computing buckets");
		HashMap<String, Bucket> bucketMap = new HashMap<>();
		for (int i = 0; i < vecs.size(); ++i) {
			Tuple2<Long, SparseVector> tp = vecs.get(i);
			stage.progress = i * 0.8 / vecs.size() + 0.1;
			IntStream.range(0, schemas.size())
					//
					.mapToObj( //
							ind -> {
								return ind + "-" + DmasByteOperation.toHexs( //
										schemas.get(ind).hash(tp._2));
							})
					.forEach(bkStr -> bucketMap.compute(bkStr, (k, v) -> {
						if (v == null)
							v = new Bucket(k);
						v.value.add(tp._1);
						return v;
					})); //
		}
		stage.complete();

		stage = progress.nextStage(this.getClass(), "Persisting buckets");
		boolean reslt = index.put(new ArrayList<>(bucketMap.values()));
		stage.complete();
		return reslt;
	}

	@Override
	public List<Tuple2<Function, Double>> query(long rid, Function func, double threshold, int topK) {
		SparseVector vec = featureGenerator.score(func);

		List<String> bkStrs = IntStream.range(0, schemas.size())
				//
				.mapToObj( //
						ind -> //
						ind + "-" + DmasByteOperation.toHexs(schemas.get(ind).hash(vec))) //
				.collect(Collectors.toList());

		return index //
				.fetch(bkStrs) //
				.stream() //
				.flatMap(bk -> objectFactory.obj_functions.queryMultiple(rid, "functionId", bk.value).collect()//
						.stream().map(bb -> new Tuple2<>(bb, 1.0)))//
				.collect(Collectors.toList());
	}

	public JavaRDD<Function> queryAsRdd(long rid, Function func, int threshold, int topK) {
		SparseVector vec = featureGenerator.score(func);

		List<String> bkStrs = IntStream.range(0, schemas.size())
				//
				.mapToObj( //
						ind -> //
						ind + "-" + DmasByteOperation.toHexs(schemas.get(ind).hash(vec))) //
				.collect(Collectors.toList());

		return index //
				.fetchAsRDD(bkStrs) //
				.flatMap(bk -> objectFactory.obj_functions.queryMultiple(rid, "functionId", bk.value).collect()
						.iterator());
	}

	@Override
	public void init() {
		index.init();
	}

	@Override
	public void close() {
		index.close();
	}

	@Override
	public JavaRDD<Tuple3<Function, Function, Double>> queryAsRdds(long rid, List<Function> targets,
			Set<Tuple2<Long, Long>> links, int topK) {
		logger.error(
				"Unsuppoted operation: this indexer does not support RDD. Please prallel the result by yourself using spark context.");
		return null;
	}

}
