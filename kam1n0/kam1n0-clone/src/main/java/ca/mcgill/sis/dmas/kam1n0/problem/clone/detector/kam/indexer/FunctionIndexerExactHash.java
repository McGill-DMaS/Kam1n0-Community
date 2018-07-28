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
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.Bucket;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketIndex;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashFunction;
import scala.Tuple2;
import scala.Tuple3;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashFunction.HashFunctionType;

public class FunctionIndexerExactHash extends Indexer<Function> {

	private HashFunction func;
	private HashFunctionType type;
	private AsmObjectFactory objectFactory;
	private AsmLineNormalizer normalizer;

	private BucketIndex index;

	private Logger logger = LoggerFactory.getLogger(FunctionIndexerExactHash.class);

	public FunctionIndexerExactHash(SparkInstance instance, AsmObjectFactory objectFactory, BucketIndex index,
			AsmLineNormalizer normalizer, HashFunctionType type) {
		super(instance);
		this.objectFactory = objectFactory;
		this.index = index;
		this.normalizer = normalizer;
		this.type = type;
		this.func = HashFunction.getHashFunction(12345l, type);
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("indexer=", this.getClass().getSimpleName(), "normalization=",
				normalizer.setting.normalizationLevel, "hashFunc=", type);
	}

	@Override
	public boolean index(long rid, List<Function> targets, LocalJobProgress progress) {

		StageInfo stage = progress.nextStage(this.getClass(), "Computing buckets");
		HashMap<String, Bucket> bucketMap = new HashMap<>();

		for (int i = 0; i < targets.size(); ++i) {
			final int ind = i;
			stage.progress = i * 0.9 / targets.size() + 0.1;
			String bkStr = Integer.toHexString(//
					func.hash(//
							StringResources.JOINER_TOKEN.join(//
									normalizer.tokenizeAsmLines(//
											Iterables.concat(targets.get(ind))))));
			bucketMap.compute(bkStr, (k, v) -> {
				if (v == null)
					v = new Bucket(k);
				v.value.add(targets.get(ind).functionId);
				return v;
			});
		}
		stage.complete();

		stage = progress.nextStage(this.getClass(), "Persisting buckets");
		boolean reslt = index.put(new ArrayList<>(bucketMap.values()));
		stage.complete();
		return reslt;
	}

	@Override
	public List<Tuple2<Function, Double>> query(long rid, Function target, double threshold, int topK) {
		String bkStr = Integer.toHexString(//
				func.hash(//
						StringResources.JOINER_TOKEN.join(//
								normalizer.tokenizeAsmLines(//
										Iterables.concat(target)))));

		return objectFactory.obj_functions.queryMultipleBaisc(rid, "functionId", index.fetch(bkStr).value).collect()
				.stream().map(func -> new Tuple2<>(func, 1.0)).collect(Collectors.toList());
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
