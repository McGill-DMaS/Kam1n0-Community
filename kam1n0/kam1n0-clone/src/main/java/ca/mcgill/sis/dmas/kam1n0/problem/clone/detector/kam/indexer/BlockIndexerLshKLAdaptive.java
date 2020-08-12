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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.io.collection.heap.Ranker;
import ca.mcgill.sis.dmas.io.collection.heap.HeapEntry;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragmentNormalized;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.ALSH;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveBucketIndexAbstract;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveBucketIndexCassandra;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveBucketIndexRam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveDupFuncIndex;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveDupIndexCasandra;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveDupIndexRam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecFullKeyCalculator;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecInfo;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecObject;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveBucketIndexAbstract.AdaptiveBucket;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;
import scala.Tuple2;
import scala.Tuple3;
import scala.Tuple4;

public class BlockIndexerLshKLAdaptive extends Indexer<Block> implements Serializable {

	private static final long serialVersionUID = -7314692043842416054L;

	private static Logger logger = LoggerFactory.getLogger(BlockIndexerLshKLAdaptive.class);

	// Spark tuning magic number from experimentation.
	// Number of partitions for 'hid_tblk' has to be tuned
	//  - too much items per partition can easily lead to out-of-memory exceptions
	//  - too few items just creates more and more shuffling overhead between Spark cores
	// This number is well below numbers that would cause OOM (about 1000) and well above values that would start
	// wasting resources (less than 10 for very large RDDs).
	private static final int MAX_HID_TBLK_PER_PARTITION = 50;

	private transient SparkInstance sparkInstance;
	private transient AsmObjectFactory objectFactory;
	private transient ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor featureGenerator;

	private transient ALSH<VecInfoBlock, VecInfoSharedBlock> index;

	public BlockIndexerLshKLAdaptive() {
	}

	public BlockIndexerLshKLAdaptive(SparkInstance sparkInstance, CassandraInstance cassandraInstance,
			AsmObjectFactory objectFactory, FeatureConstructor featureGenerator, int startK, int maxK, int L, int m,
			HashSchemaTypes type, boolean inMem) {
		super(sparkInstance);
		this.objectFactory = objectFactory;
		this.featureGenerator = featureGenerator;
		this.sparkInstance = sparkInstance;
		this.index = new ALSH<>(sparkInstance, cassandraInstance, featureGenerator.featureElements, startK, maxK, L, m,
				type, inMem, "asm_block");
	}

	@Override
	public String params() {
		return index.params();
	}

	@Override
	public boolean index(long rid, List<Block> targets, LocalJobProgress progress) {
		List<VecObjectBlock> objs = targets.stream().map(tar -> new VecObjectBlock(tar, featureGenerator))
				.collect(Collectors.toList());
		return index.index(rid, objs, progress);
	}

	@Override
	public List<Tuple2<Block, Double>> query(long rid, Block blk, double threshold, int topK) {

		ArrayListMultimap<Long, Double> candidates = ArrayListMultimap.create();
		VecObjectBlock obj = new VecObjectBlock(blk, featureGenerator);

		// get all the valid hids to a list
		List<VecEntry<VecInfoBlock, VecInfoSharedBlock>> infos = index.query(rid, Arrays.asList(obj), topK, null)._2
				.collect();

		infos.forEach(entry -> {
			double score = index.distApproximate(entry, obj);
			entry.vids.stream().forEach(blkInfo -> candidates.put(blkInfo.blockId, score));
		});

		Ranker<Long> rank = new Ranker<>(topK);
		candidates.keySet().stream().forEach(candidateId -> {
			double score = candidates.get(candidateId).stream().mapToDouble(val -> val).average().getAsDouble();
			if (rank.size() >= topK) {
				HeapEntry<Long> first = rank.peekFirst();
				if (first.score < score) {
					rank.push(score, candidateId);
				}
			} else
				rank.push(score, candidateId);
		});

		Map<Long, Double> map = rank.stream().collect(Collectors.toMap(ent -> ent.value, ent -> ent.score));
		ArrayList<Tuple2<Block, Double>> result = new ArrayList<>();

		objectFactory.obj_blocks.queryMultipleBaisc(rid, "blockId", new HashSet<>(map.keySet())).collect()
				.forEach(bb -> {
					result.add(new Tuple2<Block, Double>(bb, map.get(bb.blockId)));
				});

		return result;
	}

	public JavaPairRDD<Long, Long> collectAndFilter(JavaPairRDD<Long, Tuple2<Block, VecInfoBlock>> hid_tblk_info,
			Set<Tuple2<Long, Long>> links, int topK) {

		long blkSize = links.stream().filter(link -> link._1.equals(link._2)).count();

		// sbid->tbid
		JavaPairRDD<Long, Long> sbid_tbid = hid_tblk_info
				.mapToPair(tp -> new Tuple2<>(tp._2._2.blockId, tp._2._1.blockId)).distinct();

		// (sbid1,sbid2,fid)
		JavaRDD<Tuple3<Long, Long, Long>> sbid1_sbid2_fid = hid_tblk_info //
				.flatMap(tp -> {
					List<Tuple3<Long, Long, Long>> ls = Arrays.stream(tp._2._2.calls)
							.map(callee -> new Tuple3<>(tp._2._2.blockId, callee, tp._2._2.functionId))
							.collect(Collectors.toList());
					ls.add(new Tuple3<>(tp._2._2.blockId, tp._2._2.blockId, tp._2._2.functionId)); // add
					return ls.iterator();
				});

		// sbid1->(sbid2,fid)
		JavaPairRDD<Long, Tuple2<Long, Long>> sbid1_keyed = sbid1_sbid2_fid
				.mapToPair(tp -> new Tuple2<>(tp._1(), new Tuple2<>(tp._2(), tp._3())));

		// sbid1->((sbid2,fid), tbid1)
		JavaPairRDD<Long, Tuple2<Tuple2<Long, Long>, Long>> sbid1_keyed_filled = sbid1_keyed.join(sbid_tbid);

		// sbid2->(sbid1,tbid1,fid)
		JavaPairRDD<Long, Tuple3<Long, Long, Long>> sbid2_keyed = sbid1_keyed_filled
				.mapToPair(tp -> new Tuple2<>(tp._2._1._1, new Tuple3<>(tp._1, tp._2._2, tp._2._1._2)));

		// sbid2->((sbid1,tbid1,fid),tbid2)
		JavaPairRDD<Long, Tuple2<Tuple3<Long, Long, Long>, Long>> sbid2_keyed_filled = sbid2_keyed.join(sbid_tbid);

		// keyed by function
		// fid->(sbid1,tbid1,sbid2,tbid2)
		JavaPairRDD<Long, Tuple4<Long, Long, Long, Long>> f_keyed_filled = sbid2_keyed_filled.mapToPair(
				tp -> new Tuple2<>(tp._2._1._3(), new Tuple4<>(tp._2._1._1(), tp._2._1._2(), tp._1, tp._2._2)));

		//
		Ranker<Long> rank = new Ranker<>(topK);
		f_keyed_filled.groupByKey().mapToPair(tp -> {
			HashSet<Tuple2<Long, Long>> set = new HashSet<>();
			tp._2.forEach(ent -> set.add(new Tuple2<Long, Long>(ent._2(), ent._4())));
			set.retainAll(links);
			long edges = set.stream().filter(tp2 -> !tp2._1.equals(tp2._2)).count();
			long nodes = set.stream().filter(tp2 -> tp2._1.equals(tp2._2)).count();
			return new Tuple2<>(tp._1, nodes * blkSize + nodes);
		}).collect().forEach(tp -> rank.push(tp._2, tp._1));

		Set<Long> fids = rank.getKeys();

		return hid_tblk_info.filter(tp -> fids.contains(tp._2._2.functionId))
				.mapToPair(tp -> new Tuple2<>(tp._1, tp._2._2.blockId));
	}

	// hid->(tblk, info)
	public JavaPairRDD<Long, Long> collectAndFilter2(Long rid,
			JavaPairRDD<Long, Tuple2<Block, VecInfoBlock>> hid_tblk_info, Set<Tuple2<Long, Long>> links, int funcLength,
			int topK) {

		List<Tuple2<Long, Tuple2<Block, VecInfoBlock>>> hid_tbid_Map = hid_tblk_info.collect();

		final HashMap<Long, Double> counter = new HashMap<>();
		// logger.info("{} pairs", hid_tbid_Map.size());
		hid_tbid_Map.stream().forEach(tp -> counter.compute(tp._2()._2().functionId, (k, v) -> {
			// Double val = tp._3() * 1.0 / (tp._4() + threshold);
			// VecInfoBlock info = tp._2()._2;
			// Double val = info.blockLength * 1.0 * info.blockLength;// * 1.0 /
			// (info.peerSize) ;//+ funcLength);
			// if (v == null)
			// return val;
			// else
			// return v + val;
			// Double val = tp._3() * 1.0 / (tp._4() + threshold);
			VecInfoBlock info = tp._2()._2;
			Double val = info.blockLength * 1.0 / (info.peerSize + funcLength);
			if (v == null)
				return val;
			else
				return v + val;
		}));
		Ranker<Long> filtered = new Ranker<>();
		counter.entrySet().stream().forEach(ent -> filtered.push(ent.getValue(), ent.getKey()));
		HashSet<Long> valids = filtered.getTopK(topK * 3).stream().map(ent -> ent.value)
				.collect(Collectors.toCollection(HashSet::new));
		// List<Entry<Long, Double>> ls =
		// counter.entrySet().parallelStream().sorted((e1,e2)->e2.getValue().compareTo(e1.getValue())).collect(Collectors.toList());
		// Set<Long> valids = ls.subList(0, Math.min(topK,
		// ls.size())).stream().map(ent->ent.getKey()).collect(Collectors.toSet());
		return hid_tblk_info.filter(tp -> valids.contains(tp._2._2.functionId))
				.mapToPair(tp -> new Tuple2<>(tp._1, tp._2._2.blockId));
	}

	public static class VecInfoBlockFilter implements Serializable, Function<List<VecInfoBlock>, List<VecInfoBlock>> {

		private static final long serialVersionUID = -5140694331617864078L;
		public int blk_size;
		public int topK;

		public VecInfoBlockFilter(int blk_size, int topK) {
			this.blk_size = blk_size;
			this.topK = topK;
		}

		public VecInfoBlockFilter() {
		}

		@Override
		public List<VecInfoBlock> apply(List<VecInfoBlock> ls) {
			if (ls.size() < this.topK)
				return ls;
			Ranker<VecInfoBlock> rk = new Ranker<>();
			ls.stream().forEach(vb -> rk.push(-1 * Math.abs(vb.peerSize - this.blk_size), vb));
			return rk.getTopK(this.topK).stream().map(ent -> ent.value).collect(Collectors.toList());
		}

	}

	@Override
	public JavaRDD<Tuple3<Block, Block, Double>> queryAsRdds(long rid, List<Block> blks, Set<Tuple2<Long, Long>> links,
			int topK) {

		String functionName = blks.isEmpty() ? "Unknown_empty_function" : blks.get(0).functionName;
		int length = blks.stream().mapToInt(blk -> blk.codes.size()).sum();
		List<VecObjectBlock> objs = blks.stream().map(tar -> new VecObjectBlock(tar, featureGenerator))
				.collect(Collectors.toList());

		// hid->tbid
		// hids
		// hid_sbid_sfid
		// sfid_(hid,sbid)
		// reduce by key get sfids.
		// hid_sbid_sfid filter sfids.
		// hid->tbid join hid_sbid_sfid mappair sfid->sid_tbid

		// tbid: target block id
		// sbid: source block id
		// tblk: target block
		// sblk: souce block
		// hid: hash id

		// hid->tbid
		// List<Tuple2<Long, Block>> hid_tbid_l = bucketIndex.collectHids(blks);
		// JavaPairRDD<Long, Block> hid_tblk =
		// sparkInstance.getContext().parallelizePairs(hid_tbid_l);

		// hids
		// HashSet<Long> hids = hid_tbid_l.stream().map(tp ->
		// tp._1).collect(Collectors.toCollection(HashSet::new));

		// hid->info
		int blk_size = blks.stream().mapToInt(blk -> (int) blk.codesSize).sum();
		// new VecInfoBlockFilter(blk_size, topK)
		Tuple2<List<Tuple2<Long, VecObjectBlock>>, JavaRDD<VecEntry<VecInfoBlock, VecInfoSharedBlock>>> tp2 = index
				// .query(rid, objs, topK, null);
				.query(rid, objs, topK, new VecInfoBlockFilter(blk_size, topK * 10));

		JavaPairRDD<Long, Block> hid_tblk = sparkInstance.getContext().parallelizePairs(tp2._1.stream().map(tp -> {
			return new Tuple2<>(tp._1, tp._2.block);
		}).collect(Collectors.toList()), tp2._1.size() / MAX_HID_TBLK_PER_PARTITION + 1);
		//logger.info("kam77 hid_tblk {} items, {} partitions", hid_tblk.count(), hid_tblk.getNumPartitions());

		// @SuppressWarnings("unused")
		// List<VecEntry<VecInfoBlock, VecInfoSharedBlock>> tmp = tp2._2.collect();
		JavaPairRDD<Long, VecInfoBlock> hid_info = tp2._2.flatMapToPair(entry -> entry.vids.stream()
				.map(info -> new Tuple2<>(entry.hashId, info)).collect(Collectors.toList()).iterator());


		// filter:
		// hid->(tblk, info)
		int junctionNumPartitions = Math.max(hid_tblk.getNumPartitions(), hid_info.getNumPartitions());
		JavaPairRDD<Long, Tuple2<Block, VecInfoBlock>> jointed = hid_tblk.join(hid_info, junctionNumPartitions);
		//logger.info("kam77 jointed {} items, {} partitions", jointed.count(), jointed.getNumPartitions());
		JavaPairRDD<Long, Long> hid_sbid = this.collectAndFilter2(rid, jointed, links, length, topK);
		//logger.info("kam77 hid_sbid {} items, {} partitions", hid_sbid.count(), hid_sbid.getNumPartitions());
		HashSet<Long> sids = new HashSet<>(hid_sbid.map(tp -> tp._2).collect());

		// if (debug)
		// logger.info("sids {} func {} size {} blks {}", sids.size(),
		// blks.get(0).functionName, length, blks.size());
		JavaPairRDD<Long, Block> sbid_sblk = objectFactory.obj_blocks.queryMultipleBaisc(rid, "blockId", sids)
				.mapToPair(blk -> new Tuple2<>(blk.blockId, blk));
		//logger.info("kam77 sbid_sblk {} items, {} partitions", sbid_sblk.count(), sbid_sblk.getNumPartitions());

		int firstJunctionNumPartitions = Math.max(hid_tblk.getNumPartitions(), hid_sbid.getNumPartitions());
		int secondJunctionNumPartitions = Math.max(firstJunctionNumPartitions, sbid_sblk.getNumPartitions());
		JavaRDD<Tuple2<Block, Block>> tblk_sblk = hid_tblk.join(hid_sbid, firstJunctionNumPartitions)
				.mapToPair(tp -> new Tuple2<Long, Block>(tp._2._2, tp._2._1)).join(sbid_sblk, secondJunctionNumPartitions).map(tp -> tp._2);
		//logger.info("kam77 tblk_sblk {} items, {} partitions", tblk_sblk.count(), tblk_sblk.getNumPartitions());
		//logger.info("kam77 tblk_sblk {} partitions {}", tblk_sblk.getNumPartitions(), functionName);
		return tblk_sblk.map(tp -> new Tuple3<>(tp._1, tp._2, 1d));
	}

	@Override
	public void init() {
		index.init();
	}

	@Override
	public boolean dump(String path) {
		index.dump(path);
		return true;
	}

	@Override
	public void close() {
		index.close();
	}

	@Override
	public void clear(long rid) {
		index.clear(rid);
	}

}
