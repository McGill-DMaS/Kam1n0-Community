package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.io.array.DmasVectorDistances;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.ALSH;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecEntry;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;
import scala.Tuple2;

public class GeneralVectorIndex {

	public GeneralVectorIndex(SparkInstance sparkInstance, CassandraInstance cassandraInstance, int dim, int startK,
			int maxK, int L, int m, HashSchemaTypes type, boolean inMem) {
		List<String> features = IntStream.range(0, dim).mapToObj(ind -> "feature-" + ind).collect(Collectors.toList());
		this.index = new ALSH<>(sparkInstance, cassandraInstance, features, startK, maxK, L, m, type, inMem,
				"vec_alsh");
		this.index.init();
	}

	private transient ALSH<VecInfoArray, VecInfoSharedArray> index;

	public List<Tuple2<Long, Double>> query(long rid, double[] vec, int topK, long identifier) {
		VecObjectArray obj = new VecObjectArray(vec, identifier);
		HashMap<Long, double[]> candidates = new HashMap<>();
		List<VecEntry<VecInfoArray, VecInfoSharedArray>> infos = index.query(rid, Arrays.asList(obj), null)._2
				.collect();
		infos.forEach(info -> {
			info.vids.stream().forEach(vid -> {
				if (!candidates.containsKey(vid.identifer)) {
					candidates.put(vid.identifer, info.sharedInfo.vec);
				}
			});
		});
		return candidates.entrySet().stream()
				.map(ent -> new Tuple2<>(ent.getKey(), DmasVectorDistances.cosine(ent.getValue(), vec)))
				.sorted((t1, t2) -> Double.compare(t2._2, t1._2)).collect(Collectors.toList());
	}

	public void index(long rid, LocalJobProgress progress, List<Tuple2<Long, double[]>> vecs) {
		List<VecObjectArray> targets = vecs.stream().map(tp -> new VecObjectArray(tp._2, tp._1))
				.collect(Collectors.toList());
		index.index(rid, targets, progress);
	}

	public void index(long rid, List<Tuple2<Long, double[]>> vecs) {
		index(rid, new LocalJobProgress(), vecs);
	}

	public void index(long rid, long identifier, double[] vec) {
		this.index(rid, Arrays.asList(new Tuple2<>(identifier, vec)));
	}

	public static void main(String[] args) {
		Environment.init();
		long rid = 32;
		LocalJobProgress.enablePrint = true;
		int dim = 200;
		int cnt = 100;
		List<Tuple2<Long, double[]>> vecs = LongStream.range(0, cnt).mapToObj(ind -> {
			double[] vec = new double[dim];
			Random random = new Random();
			for (int i = 0; i < dim; ++i)
				vec[i] = random.nextGaussian();
			return new Tuple2<>(ind, vec);
		}).collect(Collectors.toList());

		CassandraInstance cassandra = CassandraInstance.createEmbeddedInstance("test", true, false);
		cassandra.init();
		SparkInstance spark = SparkInstance.createLocalInstance(cassandra.getSparkConfiguration());
		spark.init();
		cassandra.setSparkInstance(spark);

		GeneralVectorIndex index = new GeneralVectorIndex(spark, cassandra, dim, 4, 128, 15, 200,
				HashSchemaTypes.SimHash, false);
		index.index(rid, vecs);

		Tuple2<Long, double[]> query = vecs.get(0);
		List<Tuple2<Long, Double>> result = index.query(rid, query._2, 10, query._1);

		System.out.println(result.toString());
		System.out.println(result.size());

		List<Tuple2<Long, Double>> truth = vecs.stream()
				.map(vec -> new Tuple2<>(vec._1, DmasVectorDistances.cosine(vec._2, query._2)))
				.sorted((t1, t2) -> Double.compare(t2._2, t1._2)).limit(20).collect(Collectors.toList());
		System.out.println(truth);

		cassandra.close();
		spark.close();

	}

	public void clear(long rid) {
		this.index.clear(rid);
	}

}
