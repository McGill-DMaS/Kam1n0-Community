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
package ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.PreparedStatement;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.datastax.spark.connector.japi.CassandraJavaUtil.*;


import com.datastax.spark.connector.cql.CassandraConnector;
import com.datastax.spark.connector.japi.rdd.CassandraJavaRDD;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.Bucket;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketIndex;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class BucketIndexCassandra extends BucketIndex {

	private static Logger logger = LoggerFactory.getLogger(BucketIndexCassandra.class);

	private CassandraInstance cassandraInstance;
	private SparkInstance sparkInstance;
	public String databaseName = StringResources.STR_EMPTY;

	public BucketIndexCassandra(CassandraInstance cassandraInstance, SparkInstance sparkInstance, String databaseName) {
		this.cassandraInstance = cassandraInstance;
		this.sparkInstance = sparkInstance;
		this.databaseName = databaseName;
	}

	// classes:
	public static final String _BUCKETDB_B = "BUCKETDB".toLowerCase();

	// properties:
	public static final String _BUCKETDB_B_ID = "key";
	public static final String _BUCKETDB_B_VA = "value";

	public void createSchema() {

		if (!cassandraInstance.checkColumnFamilies(sparkInstance.getConf(), databaseName, _BUCKETDB_B)) {
			logger.info("Creating table: {}.{}", databaseName, _BUCKETDB_B);
			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				session.execute("CREATE KEYSPACE IF NOT EXISTS " + databaseName + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");

				session.execute("create table if not exists " + databaseName + "." + _BUCKETDB_B + " (" //
						+ _BUCKETDB_B_ID + " varchar primary key," //
						+ _BUCKETDB_B_VA + " set<bigint>" //
						+ ");");
			});
		} else {
			logger.info("Found table: {}.{}", databaseName, _BUCKETDB_B);
		}
	}

	@Override
	public void init() {
		createSchema();
	}

	@Override
	public boolean close() {
		return true;
	}

	public String getSetStatement() {
		return "UPDATE " + databaseName + "." + _BUCKETDB_B + " SET " + _BUCKETDB_B_VA + " = " + _BUCKETDB_B_VA
				+ " + ? WHERE " + _BUCKETDB_B_ID + " = ?;";
	}

	// public String joinValues(HashSet<Long> values){
	//
	// }

	@Override
	public boolean put(String bucketID, long value) {
		CassandraConnector connector = CassandraConnector.apply(sparkInstance.getConf());
		try (CqlSession session = connector.openSession()) {
			HashSet<Long> set = new HashSet<>();
			set.add(value);
			PreparedStatement statement = session.prepare(getSetStatement());
			session.execute(statement.bind(set, bucketID));
			return true;
		}
	}

	@Override
	public boolean put(String bucketID, HashSet<Long> values) {
		CassandraConnector connector = CassandraConnector.apply(sparkInstance.getConf());
		try (CqlSession session = connector.openSession()) {
			PreparedStatement statement = session.prepare(getSetStatement());
			session.execute(statement.bind(values, bucketID));
			return true;
		}
	}

	@Override
	public boolean put(ArrayList<Bucket> data) {
		CassandraConnector connector = CassandraConnector.apply(sparkInstance.getConf());
		try (CqlSession session = connector.openSession()) {
			for (Bucket bucket : data) {
				PreparedStatement statement = session.prepare(getSetStatement());
				session.execute(statement.bind(bucket.value, bucket.key));
			}
			return true;
		}
	}

	@Override
	public boolean drop(String bucketID, long value) {
		cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
			PreparedStatement statement = session.prepare("DELETE " + _BUCKETDB_B_VA + " [?] FROM " + databaseName + "." + _BUCKETDB_B + " where "
					+ _BUCKETDB_B_ID + " = ?");
			session.execute(statement.bind(value,bucketID));
		});
		return true;
	}

	@Override
	public boolean drop(String bucketID) {
		cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
			PreparedStatement statement = session.prepare("DELETE FROM " + databaseName + "." + _BUCKETDB_B + " where " + _BUCKETDB_B_ID + " = ?");

			session.execute(statement.bind(bucketID));
		});

		return true;
	}

	@Override
	public List<Bucket> fetch(List<String> bucketIDs) {
		JavaSparkContext sc = sparkInstance.getContext();
		CassandraJavaRDD<Bucket> rdd2 = javaFunctions(sc)
				.cassandraTable(databaseName, _BUCKETDB_B, mapRowTo(Bucket.class))
				.where(_BUCKETDB_B_ID + " in ?", new HashSet<>(bucketIDs));
		return rdd2.collect();

	}

	@Override
	public Bucket fetch(String bucketIDs) {
		JavaSparkContext sc = sparkInstance.getContext();
		CassandraJavaRDD<Bucket> rdd2 = javaFunctions(sc)
				.cassandraTable(databaseName, _BUCKETDB_B, mapRowTo(Bucket.class))
				.where(_BUCKETDB_B_ID + " = ?", bucketIDs);
		return rdd2.collect().get(0);
	}

	@Override
	public JavaRDD<Bucket> fetchAsRDD(List<String> bucketIDs) {
		JavaSparkContext sc = sparkInstance.getContext();
		CassandraJavaRDD<Bucket> rdd2 = javaFunctions(sc)
				.cassandraTable(databaseName, _BUCKETDB_B, mapRowTo(Bucket.class))
				.where(_BUCKETDB_B_ID + " in ?", new HashSet<>(bucketIDs));
		return rdd2;
	}

	public Iterable<Bucket> browse() {
		JavaSparkContext sc = sparkInstance.getContext();
		CassandraJavaRDD<Bucket> rdd2 = javaFunctions(sc).cassandraTable(databaseName, _BUCKETDB_B,
				mapRowTo(Bucket.class));
		return rdd2.collect();

	}

	public static void main(String[] args) throws Exception {
		/*
		 * Environment.init();
		 * 
		 * CassandraInstance cassandraInstance = CassandraInstance
		 * .createEmbeddedInstance("Kam1n0 test", false);
		 * 
		 * SparkInstance sparkInstance = SparkInstance
		 * .createLocalInstance(cassandraInstance.getSparkConfiguration());
		 * 
		 * sparkInstance.init(); cassandraInstance.init();
		 * 
		 * BucketIndexerCassandra indexer = new BucketIndexerCassandra(
		 * cassandraInstance, sparkInstance, "buckets");
		 * ObjectFactoryCassandraDB objectFactory = new
		 * ObjectFactoryCassandraDB( cassandraInstance, sparkInstance,
		 * "objects");
		 * 
		 * objectFactory.init(); indexer.init();
		 * 
		 * LSH64bKLScheme indexScheme = new LSH64bKLScheme(new Random(100), 100,
		 * 1, LshFamilies.SimHashS, HashFunction64BitType.Murmur_64);
		 * 
		 * long start = System.currentTimeMillis(); for (File asemblyFilePath :
		 * DmasFileOperations.select("asms", DmasFileOperations.REGEX_ALL)) {
		 * BinarySurrogate assemblyFile = BinarySurrogate.load(asemblyFilePath
		 * .getAbsoluteFile());
		 * 
		 * int lengthLimit = 4; NormalizationLevel normalization =
		 * NormalizationLevel.NORM_REG_SPECIFIC;
		 * 
		 * HashMap<Long, HashSet<Long>> bucketIdMap = new HashMap<>(); for
		 * (FunctionInputSurrogate function : assemblyFile) {
		 * 
		 * for (BlockInputSurrogate block : function) { List<String> asmLines =
		 * block.asmLines(); if (asmLines.size() < lengthLimit) continue;
		 * Iterable<String> tokens = AsmLineProcessor.tokenize( asmLines,
		 * normalization); List<String> buckets =
		 * indexScheme.calculateBuckets(tokens); for (int i = 0; i <
		 * buckets.size(); ++i) { long id = BucketIndexer.constructBucketID(
		 * buckets.get(i), i); HashSet<Long> set = bucketIdMap.get(id); if (set
		 * == null) { set = new HashSet<>(); bucketIdMap.put(id, set); }
		 * set.add(block.id); } }
		 * 
		 * } ArrayList<Bucket> buckets = new ArrayList<>(); for (Entry<Long,
		 * HashSet<Long>> entry : bucketIdMap.entrySet()) { buckets.add(new
		 * Bucket(entry.getKey(), entry.getValue())); }
		 * 
		 * objectFactory.addBinary(assemblyFile);
		 * 
		 * indexer.put(buckets);
		 * 
		 * //
		 * indexer.browse().forEach(bucket->System.out.println(bucket.toString
		 * ()));
		 * 
		 * logger.info("Finished: {}", asemblyFilePath);
		 * 
		 * }
		 * 
		 * logger.info("Times used to complete: {} ms",
		 * System.currentTimeMillis() - start);
		 * 
		 * objectFactory.close(); indexer.close(); sparkInstance.close();
		 * cassandraInstance.close();
		 */

	}

}
