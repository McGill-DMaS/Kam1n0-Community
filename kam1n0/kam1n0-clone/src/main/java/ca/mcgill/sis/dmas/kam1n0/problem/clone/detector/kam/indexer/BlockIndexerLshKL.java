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
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.Bucket;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketIndex;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;
import scala.Tuple2;
import scala.Tuple3;

public class BlockIndexerLshKL extends Indexer<Block> {

	private List<HashSchema> schemas;
	private SparkInstance sparkInstance;

	private AsmObjectFactory objectFactory;
	private FeatureConstructor featureGenerator;

	private BucketIndex index;

	private int K;
	private int L;
	private HashSchemaTypes type;

	private boolean debug = false;

	public BlockIndexerLshKL(SparkInstance sparkInstance, AsmObjectFactory objectFactory, BucketIndex index,
			FeatureConstructor featureGenerator, int K, int L, HashSchemaTypes type) {
		super(sparkInstance);
		this.objectFactory = objectFactory;
		this.index = index;
		this.featureGenerator = featureGenerator;
		this.sparkInstance = sparkInstance;

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
	public boolean index(long rid, List<Block> targets, LocalJobProgress progress) {
		StageInfo stage = progress.nextStage(this.getClass(), "Computing feature vectors");
		List<Tuple2<Long, SparseVector>> vecs = targets.stream()
				//
				.map(//
						blk -> //
						new Tuple2<>(blk.blockId, featureGenerator.score(blk)))//
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
	public List<Tuple2<Block, Double>> query(long rid, Block blk, double threshold, int topK) {
		SparseVector vec = featureGenerator.score(blk);

		List<String> bkStrs = IntStream.range(0, schemas.size())
				//
				.mapToObj( //
						ind -> //
						ind + "-" + DmasByteOperation.toHexs(schemas.get(ind).hash(vec))) //
				.collect(Collectors.toList());

		HashSet<Long> bids = index//
				.fetch(bkStrs)//
				.stream()//
				.flatMap(bk -> bk.value.stream())//
				.collect(Collectors.toCollection(HashSet::new));

		return objectFactory.obj_blocks.queryMultipleBaisc(rid, "blockId", bids).collect().stream()
				.map(bb -> new Tuple2<>(bb, 1.0)).collect(Collectors.toList());
	}

	@Override
	public JavaRDD<Tuple3<Block, Block, Double>> queryAsRdds(long rid, List<Block> blks, Set<Tuple2<Long, Long>> links,
			int topK) {

		// tblock -> signature map

		final ArrayList<Tuple2<String, Block>> ls_sig_tb = new ArrayList<>();
		final ArrayList<String> sigs = new ArrayList<>();
		blks.forEach(blk -> {
			SparseVector vec = this.featureGenerator.score(blk);
			List<String> bukStrs = IntStream.range(0, schemas.size()).mapToObj( //
					ind -> //
			ind + "-" + DmasByteOperation.toHexs(schemas.get(ind).hash(vec))) //
					.collect(Collectors.toList());
			bukStrs.forEach(bukStr -> ls_sig_tb.add(new Tuple2<>(bukStr, blk)));
			sigs.addAll(bukStrs);
		});

		JavaPairRDD<String, Block> sig_tb = sparkInstance.getContext().parallelize(ls_sig_tb).mapToPair(tp -> tp);

		if (debug)
			sig_tb.foreach(System.out::println);

		// signature -> sblock map
		JavaPairRDD<String, Long> sig_sbId = index.fetchAsRDD(sigs).flatMap(bucket -> {
			final ArrayList<Tuple2<String, Long>> ls = new ArrayList<>();
			bucket.value.forEach(val -> ls.add(new Tuple2<String, Long>(bucket.key, val)));
			return ls.iterator();
		}).mapToPair(tp -> tp);

		if (debug)
			sig_sbId.foreach(System.out::println);

		JavaPairRDD<Long, Block> sbId_sb = objectFactory.obj_blocks
				.queryMultipleBaisc(rid, "blockId", sig_sbId.map(tp -> tp._2).collect())
				.mapToPair(blk -> new Tuple2<>(blk.blockId, blk));

		if (debug)
			System.out
					.println(sig_tb.join(sig_sbId).mapToPair(tp -> new Tuple2<>(tp._2._2, tp._2._1)).join(sbId_sb)
							.map(tp -> tp._2).collect().stream().map(ite -> ite._1.functionName + "   "
									+ ite._2.binaryName + "   " + ite._2.functionName + "   " + ite._2.peerSize)
							.count());

		return sig_tb.join(sig_sbId).mapToPair(tp -> new Tuple2<>(tp._2._2, tp._2._1)).join(sbId_sb)
				.map(tp -> new Tuple3<>(tp._2._1, tp._2._2, 1d));
	}

	@Override
	public void init() {
		index.init();

	}

	@Override
	public void close() {
		index.close();
	}

}
