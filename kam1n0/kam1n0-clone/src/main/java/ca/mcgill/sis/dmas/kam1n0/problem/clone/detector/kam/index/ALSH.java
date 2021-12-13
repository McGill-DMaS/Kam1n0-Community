package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.LshAdaptiveBucketIndexAbstract.AdaptiveBucket;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;
import scala.Tuple2;
import scala.Tuple3;

public class ALSH<T extends VecInfo, K extends VecInfoShared> implements Serializable {

	private static final long serialVersionUID = -5210722050068882233L;

	private static final Logger logger = LoggerFactory.getLogger(ALSH.class);

	// Spark tuning magic number from experimentation.
	// In all experiments, it was faster in general (and not more memory intensive) to use a single RDD partition to
	// store "HID infos", and there are typically less than 100 HIDs per analyzed function, and very rarely above 1000.
	// However, as a fail-safe in the case of a totally degenerate function (like 100000 HIDs), a limit of
	// 1000 HID per RDD partition is applied.
	private static final int MAX_HIDS_PER_PARTITION = 1000;

	public final boolean debug = false;
	public transient LshAdaptiveDupFuncIndex<T, K> index_deduplication;
	public transient LshAdaptiveBucketIndexAbstract index_bucket;
	private transient ArrayList<HashSchema> schemas;
	private final int startingK;
	private final int maxK;
	private final HashSchemaTypes type;
	private final int L;

	/**
	 * @param isSingleUserApplication Must be false on multi-user/app use cases, optionally true otherwise. When reusing
	 *                              an existing indexer DB, must be the same than when it was created (must depend on
	 *                              use case, not on any configurable parameter). When set, it optimizes some underlying
	 *                              DB tables by assuming that any 'user-application ID' is always the same and can be
	 *                              ignored.
	 */
	public ALSH(SparkInstance sparkInstance, CassandraInstance cassandraInstance, List<String> features, int startingK,
			int maxK, int L, int m, HashSchemaTypes type, boolean inMem, String name, boolean isSingleUserApplication) {
		this.startingK = startingK;
		this.maxK = maxK;

		if (inMem) {
			this.index_bucket = new LshAdaptiveBucketIndexRam(sparkInstance, startingK, maxK, m, ALSH::nextDepth);
			this.index_deduplication = new LshAdaptiveDupIndexRam<>(sparkInstance);
		} else {
			String databaseName = name + "_adaptivelsh";
			this.index_bucket = new LshAdaptiveBucketIndexCassandra(sparkInstance, cassandraInstance, startingK, maxK,
					m, ALSH::nextDepth, databaseName);
			this.index_deduplication = new LshAdaptiveDupIndexCasandra<>(sparkInstance, cassandraInstance,
					databaseName, isSingleUserApplication);
		}

		this.L = L;
		this.type = type;

		schemas = new ArrayList<>(L);
		Random rand = new Random(1234);
		for (int i = 0; i < L; ++i)
			schemas.add(HashSchema.getHashSchema(features, this.type, this.maxK, rand));
	}

	private <E extends VecObject<T, K>> List<byte[]> hash(E obj) {
		List<byte[]> hashes = new ArrayList<byte[]>();
		schemas.forEach(schema -> hashes.add(obj.hash(schema)));
		return hashes;
	}

	private <E extends VecObject<T, K>> List<VecEntry<T, K>> create(long rid, List<E> objects, int L,
			LocalJobProgress progress) {
		HashMap<Long, VecEntry<T, K>> vecMap = new HashMap<>();
		StageInfo stage = progress.nextStage(LshAdaptiveDupFuncIndex.class, "Preparing queries... ");
		objects.forEach(blk -> {
			long hid = blk.getUniqueHash();
			for (int ind = 0; ind < L; ++ind) {
				Long id = HashUtils.constructID(//
						DmasByteOperation.getBytes(ind), //
						DmasByteOperation.getBytes(hid));
				VecEntry<T, K> vc = vecMap.get(id);
				if (vc != null)
					vc.vids.add(blk.getSelfInfo());
				else {
					vc = new VecEntry<>();
					vc.fullKey = null;
					vc.ind = ind;
					vc.vids.add(blk.getSelfInfo());
					vc.hashId = id;
					vc.sharedInfo = blk.getSharedInfo();
					vc.calculator = blk.getFullKeyCalculator(this.schemas.get(ind));
					vecMap.put(id, vc);
				}
			}
		});

		List<VecEntry<T, K>> vals = vecMap.values().stream().collect(Collectors.toList());

		stage.complete();
		stage = progress.nextStage(LshAdaptiveDupFuncIndex.class,
				"Updating deduplicated database " + vals.size() + " vecs");

		List<VecEntry<T, K>> nonexisted = index_deduplication.update(rid, vals, stage);

		stage.complete();

		return nonexisted;
	}

	public <E extends VecObject<T, K>> boolean index(long rid, List<? extends E> targets, LocalJobProgress progress) {
		List<VecEntry<T, K>> vecs = this.create(rid, targets, this.L, progress);

		StageInfo stage = progress.nextStage(this.getClass(), "Computing/Persisting buckets " + vecs.size() + " vecs");
		List<AdaptiveBucket> bks_to_split = this.index_bucket.indexVecs(rid, vecs, stage);
		HashMap<String, AdaptiveBucket> buckets = new HashMap<>();
		bks_to_split.forEach(bk -> buckets.compute(bk.pkey + bk.cKey, (k, v) -> v == null ? bk : v));
		stage.complete();

		StageInfo stage2 = progress.nextStage(this.getClass(), "Spliting " + buckets.size() + " buckets");
		Counter counter = new Counter();
		buckets.values().parallelStream().forEach(bucket -> {
			// AdaptiveBucket bucket = bks_to_split.get(bInd);
			// splitBucket(rid, bucket);
			splitBucketRecursive(rid, bucket);
			counter.inc();
			stage2.progress = counter.getVal() * 1.0 / bks_to_split.size();
		});
		stage2.complete();

		if (debug) {
			this.dump(".");
		}

		return true;
	}

	private static Integer nextDepth(Integer depth) {
		return depth * 2;
	}

	private void splitBucket(long rid, AdaptiveBucket bucket) {
		final String partitionKey;
		if (bucket.cKey.equals(LshAdaptiveBucketIndexAbstract.rootClusteringKey))
			partitionKey = bucket.pkey;
		else
			partitionKey = bucket.pkey + bucket.cKey;
		int nextDepth = nextDepth(bucket.depth);
		List<Tuple3<String, String, Long>> children = this.index_deduplication
				.getVecEntryInfoAsRDD(rid, bucket.hids, true, null, LshAdaptiveDupFuncIndex.ALL_HIDS_IN_ONE_PARTITION)
				.map(vec -> {
					int ind = vec.ind;
					String nextKey = StringResources.FORMAT_3R.format(ind) + "-"
							+ DmasByteOperation.toHexs(vec.fullKey, nextDepth);
					String clusteringKey = nextKey.replaceAll(partitionKey, "");
					return new Tuple3<>(partitionKey, clusteringKey, vec.hashId);
				}).collect();
		this.index_bucket.splitAdaptiveBucket(rid, bucket, nextDepth, children);
	}

	private void splitBucketRecursive(long rid, AdaptiveBucket bucket) {
		if (bucket.depth >= this.index_bucket.maxDepth)
			return;
		List<VecEntry<T, K>> children = this.index_deduplication.getVecEntryInfoAsRDD(
				rid, bucket.hids, true, null, LshAdaptiveDupFuncIndex.ALL_HIDS_IN_ONE_PARTITION)
				.collect();
		splitBucketRecursiveHandler(rid, bucket.pkey, bucket.cKey, bucket.depth, children);
	}

	private void splitBucketRecursiveHandler(long rid, String plk, String clk, int depth,
			List<VecEntry<T, K>> children) {
		if (depth >= this.index_bucket.maxDepth) {
			children.forEach(vec -> this.index_bucket.putHid(rid, plk, clk, depth, vec.hashId));
			return;
		}
		// logger.info("Spliting depth {} with {}::{}", depth, plk, clk);
		this.index_bucket.clearHid(rid, plk, clk);
		String partitionKey;
		if (clk.equals(LshAdaptiveBucketIndexAbstract.rootClusteringKey))
			partitionKey = plk;
		else
			partitionKey = plk + clk;
		int nextDepth = nextDepth(depth);
		ArrayListMultimap<String, VecEntry<T, K>> map = ArrayListMultimap.create();
		children.stream().forEach(vec -> {
			int ind = vec.ind;
			String nextKey = StringResources.FORMAT_3R.format(ind) + "-"
					+ DmasByteOperation.toHexs(vec.fullKey, nextDepth);
			String clusteringKey = nextKey.replaceAll(partitionKey, "");
			map.put(clusteringKey, vec);
		});
		map.keySet().stream().forEach(k -> {
			List<VecEntry<T, K>> vecs = map.get(k);
			if (vecs.size() < this.index_bucket.maxSize) {
				vecs.parallelStream()
						.forEach(vec -> this.index_bucket.putHid(rid, partitionKey, k, nextDepth, vec.hashId));
			} else {
				splitBucketRecursiveHandler(rid, partitionKey, k, nextDepth, vecs);
			}
		});
	}

	public <E extends VecObject<T, K>> Tuple2<List<Tuple2<Long, E>>, JavaRDD<VecEntry<T, K>>> query(long rid,
			List<? extends E> objs, Function<List<T>, List<T>> filter) {
		List<Tuple2<Long, E>> hid_tbid_l = this.index_bucket.collectHids(rid, objs, this::hash);
		HashSet<Long> hids = hid_tbid_l.stream().map(tp -> tp._1).collect(Collectors.toCollection(HashSet::new));

		// hid->info
		JavaRDD<VecEntry<T, K>> hid_info = this.index_deduplication.getVecEntryInfoAsRDD(
				rid, hids, false, filter, MAX_HIDS_PER_PARTITION);// .cache();

		return new Tuple2<>(hid_tbid_l, hid_info);
	}

	public void dump(String file) {
		logger.info("Dumping bucket index...");
		index_deduplication.dump(file + "/bucketIndex.split.json");
		logger.info("Dumping hashid index...");
		index_bucket.dump(file + "/hashIndex.split.json");
		logger.info("Completed");
	}

	public void init() {
		this.index_deduplication.init();
		this.index_bucket.init();

	}

	public void close() {
		this.index_deduplication.close();
		this.index_bucket.close();
	}

	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("indexer=", this.getClass().getSimpleName(), "K_s=", startingK,
				"K_m=", maxK, "L=", L, "LshType=", type);
	}

	public double distApproximate(VecEntry<T, K> entry, VecObject<T, K> obj) {
		HashSchema schema = this.schemas.get(entry.ind);
		return schema.distApprox(entry.fullKey, obj.hash(schema), entry.fullKey.length);
	}

	public void clear(long rid) {
		this.index_bucket.clearAll(rid);
		this.index_deduplication.clear(rid);
	}
}
