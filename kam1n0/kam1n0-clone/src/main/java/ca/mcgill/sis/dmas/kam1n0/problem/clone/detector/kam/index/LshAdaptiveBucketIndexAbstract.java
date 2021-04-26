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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.spark.api.java.JavaPairRDD;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;
import scala.Tuple2;
import scala.Tuple3;

/**
 * user/repository isolation, L isoliation, is done through building different
 * prefix into the primary key.
 */
public abstract class LshAdaptiveBucketIndexAbstract {

	public int initialDepth;
	public int maxDepth;
	public int maxSize;

	public Function<Integer, Integer> nextDepth;

	public transient SparkInstance sparkInstance;

	// private static Logger logger =
	// LoggerFactory.getLogger(LshAdaptiveBucketIndexAbstract.class);

	public LshAdaptiveBucketIndexAbstract(SparkInstance sparkInstance, int initialDepth, int maxDepth, int maxSize,
			Function<Integer, Integer> nextDepth) {
		this.sparkInstance = sparkInstance;
		this.initialDepth = initialDepth;
		this.maxDepth = maxDepth;
		this.maxSize = maxSize;
		this.nextDepth = nextDepth;
	}

	public boolean debug = false;

	public final static String rootClusteringKey = "ZZ";

	public abstract void init();

	public abstract void close();

	public abstract HashSet<Long> getHids(long rid, String primaryKey, String secondaryKey);

	public abstract void dump(String file);

	/***
	 * Clear means remove all elements of a set but keep the key.
	 * 
	 * @param primaryKey
	 * @param secondaryKey
	 * @return
	 */
	public abstract boolean clearHid(long rid, String primaryKey, String secondaryKey);

	public abstract boolean clearAll(long rid);

	/**
	 * 
	 * @param primaryKey
	 * @param secondaryKey
	 * @param newDepth
	 *            -1 represents no changes to the original field depth
	 * @param hid
	 * @return
	 */
	public abstract boolean putHid(long rid, String primaryKey, String secondaryKey, int newDepth, Long hid);

	public abstract boolean putHid(long rid, String primaryKey, String secondaryKey, HashSet<Long> hids);

	public abstract AdaptiveBucket nextOnTheLeft(long rid, AdaptiveBucket target);

	public abstract AdaptiveBucket nextOnTheRight(long rid, AdaptiveBucket target);

	public void splitAdaptiveBucket(long rid, AdaptiveBucket target, int newDepth,
			List<Tuple3<String, String, Long>> children) {
		this.clearHid(rid, target.pkey, target.cKey);
		children.parallelStream().forEach(child -> this.putHid(rid, child._1(), child._2(), newDepth, child._3()));
	}

	public static class AdaptiveBucket {
		public String pkey;
		public String cKey;
		public Integer depth;
		public HashSet<Long> hids;

		public AdaptiveBucket(String pKey, String cKey, Integer depth, HashSet<Long> hids) {
			this.pkey = pKey;
			this.cKey = cKey;
			this.depth = depth;
			this.hids = hids;
		}
	}

	public AdaptiveBucket[] extendBuckets(long rid, AdaptiveBucket left, AdaptiveBucket right) {
		AdaptiveBucket[] res = new AdaptiveBucket[2];
		if (left != null && !left.cKey.equals(rootClusteringKey))
			res[0] = this.nextOnTheLeft(rid, left);
		if (right != null && !right.cKey.equals(rootClusteringKey))
			res[1] = this.nextOnTheRight(rid, right);
		return res;
	}

	/***
	 * 
	 * @param ind
	 * @param fullKey
	 * @return a tuple of (bucket partition key, bucket clustering key, list of
	 *         hids)
	 */
	public AdaptiveBucket locateBucket(long rid, int ind, byte[] fullKey) {

		// query root:
		int dept = initialDepth;
		String prefix = StringResources.FORMAT_3R.format(ind) + "-";
		String partitionKey = prefix + DmasByteOperation.toHexs(fullKey, dept);
		String clusteringKey = rootClusteringKey;
		HashSet<Long> hids = this.getHids(rid, partitionKey, clusteringKey);

		// if hids is null; then it means no root bucket matached; create an
		// empty one. if the caller find the returned bucket has a hids of size
		// zero: means it is newly created. Otherwise it should be located in
		// the
		// deeper leve.
		if (hids == null)
			return new AdaptiveBucket(partitionKey, clusteringKey, dept, new HashSet<>());

		// if hids is not empty; we return it.
		if (hids.size() != 0)
			return new AdaptiveBucket(partitionKey, clusteringKey, dept, hids);

		String nextKey = partitionKey;
		while (hids.size() == 0 && dept < maxDepth) {
			partitionKey = nextKey;
			dept = nextDepth.apply(dept);
			nextKey = prefix + DmasByteOperation.toHexs(fullKey, dept);
			clusteringKey = nextKey.replace(partitionKey, "");

			hids = getHids(rid, partitionKey, clusteringKey);
			if (hids == null)
				return new AdaptiveBucket(partitionKey, clusteringKey, dept, new HashSet<>());
		}
		return new AdaptiveBucket(partitionKey, clusteringKey, dept, hids);

	}

	/***
	 * 
	 * @param ind
	 *            The index of a hash function (to be used as prefix for the
	 *            hash key)
	 * @param fullKey
	 *            The full hashed key according to maxDepth
	 * @return set of unique hash ids
	 */
	public HashSet<Long> getHids(long rid, int ind, byte[] fullKey) {
		AdaptiveBucket bk = locateBucket(rid, ind, fullKey);

		// in case the bucket actually cannot be found (it is tmply created)
		if (bk.hids.size() == 0)
			return new HashSet<>();

		HashSet<Long> vals = new HashSet<>(bk.hids);

		// to keep track of the expansion search
		// AdaptiveBucket left = bk;
		// AdaptiveBucket right = bk;

		// while (vals.size() <= maxSize && (left != null | right != null)) {
		// AdaptiveBucket[] expansion = this.extendBuckets(rid, left, right);
		// left = expansion[0];
		// right = expansion[1];
		// if (left != null)
		// vals.addAll(left.hids);
		// if (right != null)
		// vals.addAll(right.hids);
		// }
		// System.out.println("Collected " + vals.size() + " Depth " +
		// bk.depth);

		return vals;
	}

	public Tuple2<HashSet<Long>, Integer> getHidsWithDepth(long rid, int ind, byte[] fullKey) {
		AdaptiveBucket bk = locateBucket(rid, ind, fullKey);

		// in case the bucket actually cannot be found (it is tmply created)
		if (bk.hids.size() == 0)
			return new Tuple2<HashSet<Long>, Integer>(new HashSet<>(), 0);

		HashSet<Long> vals = new HashSet<>(bk.hids);

		// to keep track of the expansion search
		// AdaptiveBucket left = bk;
		// AdaptiveBucket right = bk;

		// while (vals.size() <= maxSize && (left != null | right != null)) {
		// AdaptiveBucket[] expansion = this.extendBuckets(rid, left, right);
		// left = expansion[0];
		// right = expansion[1];
		// if (left != null)
		// vals.addAll(left.hids);
		// if (right != null)
		// vals.addAll(right.hids);
		// }
		// System.out.println("Collected " + vals.size());

		return new Tuple2<HashSet<Long>, Integer>(vals, bk.depth);
	}

	/*
	 * list of hashId -> inputVectorId
	 */
	public <T> HashSet<Long> collectHid(long rid, T blk, Function<T, List<byte[]>> hasher) {

		// calculate full length bucket
		List<byte[]> bks = hasher.apply(blk);

		// get all the valid hids to a list
		HashSet<Long> vals = new HashSet<>();
		for (int i = 0; i < bks.size(); ++i)
			vals.addAll(getHids(rid, i, bks.get(i)));
		return vals;

	}

	/*
	 * list of hashId -> inputVectorId
	 */
	public <T extends VecObject<?, ?>> List<Tuple2<Long, T>> collectHids(long rid, List<? extends T> blks,
			Function<T, List<byte[]>> hasher) {
		return blks.stream()//
				.parallel()//
				.map(blk -> {
					// calculate full length bucket
					List<byte[]> bks = hasher.apply(blk);

					// get all the valid hids to a list
					ArrayList<Tuple2<Long, T>> vals = new ArrayList<>();
					for (int i = 0; i < bks.size(); ++i) {
						if (bks.get(i).length < 1)
							continue;
						Tuple2<HashSet<Long>, Integer> hids = getHidsWithDepth(rid, i, bks.get(i));
						Long bhid = blk.getUniqueHash();
						Long id = HashUtils.constructID(//
								DmasByteOperation.getBytes(i), //
								DmasByteOperation.getBytes(bhid));
						// System.out.println(
						// "hids " + hids._1.size() + " contains? " +
						// hids._1.contains(id) + " " +
						// blk.toString() + " " + id);
						if (hids._1.size() < this.maxSize)
							for (Long hid : getHids(rid, i, bks.get(i))) {
								vals.add(new Tuple2<Long, T>(hid, blk));
							}
						else {
							vals.add(new Tuple2<Long, T>(id, blk));
						}
					}
					return vals;

				}).filter(ls -> ls != null).flatMap(// flat map the list (merge
													// from different thread)
						ls -> //
						ls.stream())//
				.filter(x -> x != null).collect(Collectors.toList());
	}

	/*
	 * PairRDDs of hashId -> inputVectorId
	 */
	public <T extends VecObject<?, ?>> JavaPairRDD<Long, T> collectHidsAsRdd(long rid, List<? extends T> vecs,
			Function<T, List<byte[]>> hasher) {
		return sparkInstance.getContext().parallelizePairs(this.collectHids(rid, vecs, hasher));
	}

	public List<AdaptiveBucket> indexVecs(long rid,
			List<? extends VecEntry<? extends VecInfo, ? extends VecInfoShared>> vecs, StageInfo stage) {
		Counter counter = new Counter();
		int total = vecs.size();
		List<AdaptiveBucket> ls = vecs
				//
				.parallelStream().map(vec -> {
					if (vec.fullKey.length == 0) {
						return null;
					}
					AdaptiveBucket adBk = this.locateBucket(rid, vec.ind, vec.fullKey);
					this.putHid(rid, adBk.pkey, adBk.cKey, adBk.depth, vec.hashId);
					adBk.hids.add(vec.hashId);
					counter.inc();
					stage.progress = counter.getVal() * 1.0 / total;
					if (adBk.hids.size() > maxSize && adBk.depth < maxDepth)
						return adBk;
					else
						return null;
				}).filter(adbk -> adbk != null).collect(Collectors.toList());
		HashMap<String, AdaptiveBucket> deduplicateMap = new HashMap<>();
		ls.forEach(bk -> deduplicateMap.compute(bk.pkey + bk.cKey, (k, v) -> {
			if (v == null)
				return bk;
			v.hids.addAll(bk.hids);
			return v;
		}));

		return new ArrayList<>(deduplicateMap.values());
	}
}
