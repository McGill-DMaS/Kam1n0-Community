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


import static com.datastax.oss.driver.api.querybuilder.QueryBuilder.literal;
import static com.datastax.spark.connector.japi.CassandraJavaUtil.javaFunctions;
import static com.datastax.spark.connector.japi.CassandraJavaUtil.typeConverter;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.datastax.oss.driver.api.querybuilder.QueryBuilder;
import com.datastax.oss.driver.api.core.metadata.schema.*;
import com.datastax.oss.driver.api.core.CqlSession;
import org.apache.spark.api.java.JavaRDD;
import com.datastax.spark.connector.japi.CassandraRow;
import org.apache.spark.api.java.JavaPairRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import scala.Tuple2;

public class LshAdaptiveDupIndexCasandra<T extends VecInfo, K extends VecInfoShared>
		extends LshAdaptiveDupFuncIndex<T, K> {

	private String databaseName;
	private CassandraInstance cassandraInstance;
	private boolean isSingleUserApplication;

	private static Logger logger = LoggerFactory.getLogger(LshAdaptiveDupIndexCasandra.class);

	private static final String _ADAPTIVE_HASH = "ADAPTIVE_HASH".toLowerCase();
	private static final String _ADAPTIVE_HASH_VIEW = _ADAPTIVE_HASH + "_view";
	private static final String _ADAPTIVE_HASH_VEC = _ADAPTIVE_HASH + "_vec";

	private static final String _APP_ID_COLUMN = "rid0";
	private static final String _HASHID_COLUMN = "hashid";
	private static final String _IND_COLUMN = "ind";
	private static final String _FULLKEY_COLUMN = "full_key";
	private static final String _SHARED_INFO_COLUMN = "share";
	private static final String _VEC_INFO_COLUMN = "vecinfo";


	/**
	 * @param isSingleUserApplication   When set, adaptive_hash table is partitioned by hash ID instead of rid, which is
	 * 	  							  more efficient in that case. Also, adaptive_hash_view is not required anymore.
	 * 	  							  This may only be set for single-user/app cases, and must be the same value when
	 * 	  							  creating and re-using a database. Note: 'appliation ID' ('rid0' column) is still
	 * 	  							  stored in the DB (as a clustering key) for code compatibility.
	 */
	public LshAdaptiveDupIndexCasandra(SparkInstance sparkInstance, CassandraInstance cassandraInstance,
									   String databaseName, boolean isSingleUserApplication) {
		super(sparkInstance);
		this.databaseName = databaseName;
		this.cassandraInstance = cassandraInstance;
		this.isSingleUserApplication = isSingleUserApplication;
	}

	private String getColumnsAsCsv(List<String> columnsLabels) {
		return String.join(",", columnsLabels);
	}

	private void assertExpectedKey(String tableName, String humanReadableKeyType,
								   List<String> expectedKeyColumns, List<ColumnMetadata> existingKeyColumns) {
		List<String> existingColumnLabels = existingKeyColumns.stream()
				.map(columnMeta -> columnMeta.getName().toString()).collect(Collectors.toList());

		if (!expectedKeyColumns.equals(existingColumnLabels)) {
			throw new RuntimeException("Existing " + databaseName + "." + tableName
					+ " has " + humanReadableKeyType + " key ("
					+ getColumnsAsCsv(existingColumnLabels) + ") but current use-case expects ("
					+ getColumnsAsCsv(expectedKeyColumns) + "). Cannot create or reuse table.");
		}
	}

	private void createTableOrValidateExisting(String tableName, List<String> columnLabelsAndType,
											   List<String> partitionKeyColumns, List<String> clusteringKeyColumns) {

		if (!cassandraInstance.checkColumnFamilies(this.sparkInstance.getConf(), this.databaseName, tableName)) {
			this.cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
				String createTableStatement = "create table if not exists "
						+ databaseName + "." + tableName + " ("
						+ getColumnsAsCsv(columnLabelsAndType) + ", "
						+ " PRIMARY KEY ((" + getColumnsAsCsv(partitionKeyColumns) + "), " + getColumnsAsCsv(clusteringKeyColumns) + ") "
						+ ");";
				logger.info("Creating table {}.{} with {}", this.databaseName, tableName, createTableStatement);
				session.execute(createTableStatement);

				// TODO: check materialized view existed nor not
				if (tableName.equals(_ADAPTIVE_HASH)){
					String createViewStatement = "CREATE MATERIALIZED VIEW " + databaseName + "." + _ADAPTIVE_HASH_VIEW + " AS "
							+ "SELECT * FROM " + databaseName + "." + _ADAPTIVE_HASH + " "
							+ "WHERE " + _APP_ID_COLUMN + " IS NOT NULL AND " + _HASHID_COLUMN + " IS NOT NULL AND "
							+ _IND_COLUMN + " IS NOT NULL " + "PRIMARY KEY((" + _APP_ID_COLUMN + ", "
							+ _HASHID_COLUMN + "), " + _IND_COLUMN
							+ ");";
					logger.info("Creating view {}.{} with {}", this.databaseName, _ADAPTIVE_HASH_VIEW, createViewStatement);
					session.execute(createViewStatement);
				}
		});
		} else {
			logger.info("Found table {}.{}", this.databaseName, tableName);

			// TODO: failed for 4.0 api. CQLSession no longer provides get_cluster method. Instead, it opts for metadata API.
			// cassandraInstance.doWithCluster(this.sparkInstance.getConf(), cluster -> {
			// 	TableMetadata meta = cluster.getMetadata().getKeyspace(databaseName).getTable(tableName);
			// 	assertExpectedKey(tableName, "partition", partitionKeyColumns, meta.getPartitionKey());
			// 	assertExpectedKey(tableName, "clustering", clusteringKeyColumns, meta.getClusteringColumns());
			// });
		}
	}


	private void createMainTable() {

		// Single-user-app use-cases can be optimized with finer partitioning (on hash_id), while multiple-user-app
		// use-cases remain constrained to partitioning on app ID only (this may lead to very large partitions)
		// Note that app ID column is useless in single-use-app (always -1) but was kept for compatibility with existing
		// queries.
		List<String> partitionKey = isSingleUserApplication ?
				Arrays.asList(_HASHID_COLUMN) : Arrays.asList(_APP_ID_COLUMN);
		List<String> clusteringKey = isSingleUserApplication ?
				Arrays.asList(_APP_ID_COLUMN) : Arrays.asList(_HASHID_COLUMN);

		List<String> columnsWithTypes = Arrays.asList(
				_APP_ID_COLUMN + " bigint",
				_HASHID_COLUMN + " bigint",
				_IND_COLUMN + " int",
				_FULLKEY_COLUMN + " blob",
				_SHARED_INFO_COLUMN + " text");

		createTableOrValidateExisting(_ADAPTIVE_HASH, columnsWithTypes, partitionKey, clusteringKey);
	}

	// TODO: failed for 4.0 api. CQLSession no longer provides get_cluster method. Instead, it opts for metadata API.
	// private void createViewOnTable() {

	// 	boolean hasView = cassandraInstance.doWithClusterWithReturn(this.sparkInstance.getConf(), cluster -> {
	// 		return cluster.getMetadata().getKeyspace(databaseName).getMaterializedView(_ADAPTIVE_HASH_VIEW) != null;
	// 	});

	// 	if (!hasView) {
	// 		if (!isSingleUserApplication) {
	// 			this.cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
	// 				String createViewStatement = "CREATE MATERIALIZED VIEW " + databaseName + "." + _ADAPTIVE_HASH_VIEW + " AS "
	// 						+ "SELECT * FROM " + databaseName + "." + _ADAPTIVE_HASH + " "
	// 						+ "WHERE " + _APP_ID_COLUMN + " IS NOT NULL AND " + _HASHID_COLUMN + " IS NOT NULL AND "
	// 						+ _IND_COLUMN + " IS NOT NULL " + "PRIMARY KEY((" + _APP_ID_COLUMN + ", "
	// 						+ _HASHID_COLUMN + "), " + _IND_COLUMN
	// 						+ ");";
	// 				logger.info("Creating view {}.{} with {}", this.databaseName, _ADAPTIVE_HASH_VIEW, createViewStatement);
	// 				session.execute(createViewStatement);
	// 			});
	// 		}
	// 	} else {
	// 		logger.info("Found view {}.{}", this.databaseName, _ADAPTIVE_HASH_VIEW);

	// 		if (isSingleUserApplication) {
	// 			throw new RuntimeException("Existing " + databaseName + " DB was already created for a multi-user application and can't be re-used in current single-user application");
	// 		}
	// 	}
	// }

	private void createVecTable() {

		// Single-user-app use-cases can be optimized with finer partitioning (on hash_id), while multiple-user-app
		// use-cases remain constrained to partitioning on app ID only (this may lead to very large partitions)
		// Note that app ID column is useless in single-use-app (always -1) but was kept for compatibility with existing
		// queries.
		List<String> partitionKeys = isSingleUserApplication ?
				Arrays.asList(_APP_ID_COLUMN, _HASHID_COLUMN) : Arrays.asList(_APP_ID_COLUMN);
		List<String> clusteringKeys = isSingleUserApplication ?
				Arrays.asList(_VEC_INFO_COLUMN) : Arrays.asList(_HASHID_COLUMN, _VEC_INFO_COLUMN);

		List<String> columnsWithTypes = Arrays.asList(
				_APP_ID_COLUMN + " bigint",
				_HASHID_COLUMN + " bigint",
				_VEC_INFO_COLUMN + " text");

		createTableOrValidateExisting(_ADAPTIVE_HASH_VEC, columnsWithTypes, partitionKeys, clusteringKeys);
	}


	private void createSchema() {
		this.cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
			session.execute("CREATE KEYSPACE if not exists " + databaseName + " WITH "
					+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
					+ " AND durable_writes = true;");
		});

		createMainTable();
		// createViewOnTable();
		createVecTable();
	}

	@Override
	public void init() {
		createSchema();
	}

	@Override
	public void close() {

	}

	@Override
	public List<VecEntry<T, K>> update(long rid, List<VecEntry<T, K>> vecs, StageInfo info) {
		return this.cassandraInstance.doWithSessionWithReturn(sparkInstance.getConf(), session -> {
			Counter counter = new Counter();

			return vecs.stream().parallel()
					.map(vec -> {
						if (info != null) {
							counter.inc();
							info.progress = counter.percentage(vecs.size());
						}
						return updateOrInsertVecEntry(session, rid, vec) ? vec : null;
					}).filter(vec -> vec != null)
					.collect(Collectors.toList());
		});
	}

	private boolean updateOrInsertVecEntry(CqlSession session, long rid, VecEntry<T, K> vec) {

		var res = session.execute(
				QueryBuilder.selectFrom(databaseName, _ADAPTIVE_HASH).column(_HASHID_COLUMN)
						.whereColumn(_APP_ID_COLUMN).isEqualTo(literal(rid))
						.whereColumn(_HASHID_COLUMN).isEqualTo(literal(vec.hashId)).build()).one();
						
		boolean isNewEntry = res == null;

		if (isNewEntry) {
			calFullKey(vec);
			if (vec.fullKey.length != 0) {
				session.executeAsync(QueryBuilder.insertInto(databaseName, _ADAPTIVE_HASH)
						.value(_APP_ID_COLUMN, literal(rid))
						.value(_HASHID_COLUMN, literal(vec.hashId))
						.value(_IND_COLUMN, literal(vec.ind))
						.value(_FULLKEY_COLUMN, literal(ByteBuffer.wrap(vec.fullKey)))
						.value(_SHARED_INFO_COLUMN, literal(vec.sharedInfo.serialize())).build()
				);
			}
		}

		for (T vecInfo : vec.vids) {
			session.executeAsync(QueryBuilder.insertInto(databaseName, _ADAPTIVE_HASH_VEC)
					.value(_APP_ID_COLUMN, literal(rid))
					.value(_HASHID_COLUMN, literal(vec.hashId))
					.value(_VEC_INFO_COLUMN, literal(vecInfo.serialize())).build()
					);
		}

		return isNewEntry;
	}


	public static class HidWrapper implements Serializable {
		private static final long serialVersionUID = 8243393648116173793L;

		public HidWrapper(Long hid) {
			this.hashid = hid;
		}

		public Long hashid;

		public Long getHashid() {
			return hashid;
		}

		public void setHashid(Long hashid) {
			this.hashid = hashid;
		}
	}

	// hid -> bid ( input is tbid->hid)
	// @Override
	// public JavaPairRDD<Long, Tuple2<T, D>> getVidsAsRDD(HashSet<Long> hids, int
	// topK) {
	// // remote
	// // original : functionId, hashId, blockId, blockLength, peerSize
	// // new : hashid, vecInfo
	//
	// JavaPairRDD<Long, Tuple2<T, D>> vals = javaFunctions(
	// sparkInstance.getContext().parallelize(new ArrayList<>(hids)).map(hid -> new
	// HidWrapper(hid)))
	// .joinWithCassandraTable(databaseName, _ADAPTIVE_HASH,
	// CassandraJavaUtil.someColumns(_ADAPTIVE_HASH_VIDS),
	// CassandraJavaUtil.someColumns(_ADAPTIVE_HASH_HASHID), //
	// GenericJavaRowReaderFactory.instance, //
	// CassandraJavaUtil.mapToRow(HidWrapper.class) //
	// ).filter(tp2 -> !tp2._2.isNullAt(0)).<Tuple2<Long, Tuple2<T, D>>>flatMap(tp2
	// -> {
	// Long hashId = tp2._1.hashid;
	// Set<String> vids = tp2._2.getSet(0, typeConverter(String.class));
	// return vids.stream().map(vid -> {
	// return new Tuple2<>(hashId, new Tuple2<>(VecInfo.<T>deSerialize(vid),
	// tp2._1.));
	// }).collect(Collectors.toList());
	// }).mapToPair(tp -> tp);
	//
	// return vals;

	// // (sid, (hid, fid))
	// JavaPairRDD<Long, Tuple2<Long, Long>> sid_hid_fid = vals
	// .mapToPair(entry -> new Tuple2<>(entry._2.blockId, new
	// Tuple2<>(entry._1, entry._2.functionId)));
	//
	// // (c_sid, (o_sid, o_fid o_hid))
	// JavaPairRDD<Long, Tuple3<Long, Long, Long>> csid_osid_ofid_ohid =
	// vals.flatMapToPair(entry -> {
	// return Arrays.stream(entry._2().calls)
	// .map(callee -> new Tuple2<>(callee, new Tuple3<>(entry._2.blockId,
	// entry._2.functionId, entry._1)))
	// .collect(Collectors.toList());
	// });
	//
	// // (c_sid, ((o_sid, o_fid o_hid), (c_hid, c_fid)))
	// JavaPairRDD<Long, Tuple2<Tuple3<Long, Long, Long>, Tuple2<Long,
	// Long>>> jointed = csid_osid_ofid_ohid
	// .join(sid_hid_fid).filter(tp -> tp._2._1._2() == tp._2._2._2);
	//
	// // (fid, o_hid, c_hid)
	// JavaPairRDD<Long, Tuple2<Long, Long>> slinks = jointed
	// .mapToPair(tp -> new Tuple2<>(tp._2._1._2(), new
	// Tuple2<>(tp._2._1._3(), tp._2._2._1)));
	//
	// Set<Long> tops = slinks.groupByKey().mapToPair(grouped -> {
	// long count = StreamSupport.stream(grouped._2.spliterator(),
	// false).distinct()
	// .filter(tp -> links.get(tp._1).contains(tp._2)).count();
	// return new Tuple2<>(grouped._1, count);
	// }).top(topK).stream().map(entry ->
	// entry._1).collect(Collectors.toSet());
	//
	// // finished ranking
	//
	// return vals.filter(val -> tops.contains(val._2.functionId))
	// .mapToPair(val -> new Tuple2<>(val._1, val._2.blockId));
	// }

	private static final String[] selectAllInfo = new String[] { _HASHID_COLUMN, _IND_COLUMN,
			_FULLKEY_COLUMN, _SHARED_INFO_COLUMN};
	private static final String[] selectAllInfoButVidsAndSharedInfo = new String[] { _HASHID_COLUMN,
			_IND_COLUMN, _FULLKEY_COLUMN};

	@Override
	public JavaRDD<VecEntry<T, K>> getVecEntryInfoAsRDD(long rid, HashSet<Long> hashIds, boolean excludeBlockIds,
														Function<List<T>, List<T>> vecInfosfilter, int maxHidsPerPartition) {

		String dbToQuery = isSingleUserApplication ? _ADAPTIVE_HASH : _ADAPTIVE_HASH_VIEW;

		return sparkInstance.localMode ?
				getVecEntriesOnLocalSpark(dbToQuery, rid, hashIds, excludeBlockIds, vecInfosfilter, maxHidsPerPartition) :
				getVecEntriesOnDistributedSpark(dbToQuery, rid, hashIds, excludeBlockIds, vecInfosfilter);
	}

	private JavaRDD<VecEntry<T, K>> getVecEntriesOnLocalSpark(
			String dbToQuery, long rid, HashSet<Long> hashIds,
			boolean excludeBlockIds, Function<List<T>, List<T>> vecInfosfilter, int maxHidsPerPartition) {

		List<VecEntry<T, K>> collected = cassandraInstance.doWithSessionWithReturn(sparkInstance.getConf(),
				session -> {
					return hashIds.stream().map(hid -> {
						return session.execute(QueryBuilder.selectFrom(databaseName, dbToQuery)
								.columns(excludeBlockIds ? selectAllInfoButVidsAndSharedInfo : selectAllInfo)
								.whereColumn(_APP_ID_COLUMN).isEqualTo(literal(rid))
								.whereColumn(_HASHID_COLUMN).isEqualTo(literal(hid)).build()
						).one();
					}).filter(row -> row != null).map(row -> {
						VecEntry<T, K> vec = new VecEntry<T, K>();
						vec.hashId = row.getLong(0);
						vec.ind = row.getInt(1);
						// ByteBuffer bb = row.getBytes(2);
						ByteBuffer bb = row.getByteBuffer(2);
						vec.fullKey = new byte[bb.remaining()];
						bb.get(vec.fullKey);
						if (!excludeBlockIds) {
							String shared = row.getString(3);
							vec.sharedInfo = VecInfoShared.<K>deSerialize(shared);

							final List<T> ls = new ArrayList<>();
							session.execute(QueryBuilder
									.selectFrom(databaseName, _ADAPTIVE_HASH_VEC).column(_VEC_INFO_COLUMN).whereColumn(_APP_ID_COLUMN).isEqualTo(literal(rid))
									.whereColumn(_HASHID_COLUMN).isEqualTo(literal(vec.hashId)).build()
									).forEach(vecRow -> {
								ls.add(VecInfo.<T>deSerialize(vecRow.getString(0)));
							});
							if (vecInfosfilter != null) {
								vec.vids = new HashSet<T>(vecInfosfilter.apply(ls));
							} else {
								vec.vids = new HashSet<T>(ls);
							}
						}
						return vec;
					}).collect(Collectors.toList());
				});

		int numPartitions = maxHidsPerPartition <= ALL_HIDS_IN_ONE_PARTITION ? 1 : (collected.size() / maxHidsPerPartition + 1);
		return sparkInstance.getContext().parallelize(collected, numPartitions);
	}

	private JavaRDD<VecEntry<T, K>> getVecEntriesOnDistributedSpark(
			String dbToQuery, long rid, HashSet<Long> hashIds,
			boolean excludeBlockIds, Function<List<T>, List<T>> vecInfosfilter) {

		JavaPairRDD<Long, VecEntry<T, K>> vecsByHashId = javaFunctions(sparkInstance.getContext())
				.cassandraTable(databaseName, dbToQuery)
				.select(excludeBlockIds ? selectAllInfoButVidsAndSharedInfo : selectAllInfo)
				.where(_APP_ID_COLUMN + " = ? AND " + _HASHID_COLUMN + " in ?", rid, hashIds)//
				.filter(row -> !row.isNullAt(0) && !row.isNullAt(1) & !row.isNullAt(2))
				.mapToPair(row -> {
					VecEntry<T, K> vec = new VecEntry<T, K>();
					vec.hashId = row.getLong(0);
					vec.ind = row.getInt(1);
					ByteBuffer bb = row.getBytes(2);
					vec.fullKey = new byte[bb.remaining()];
					bb.get(vec.fullKey);

					if (!excludeBlockIds) {
						String shared = row.getString(3);
						vec.sharedInfo = VecInfoShared.<K>deSerialize(shared);
					}
					return new Tuple2<>(vec.hashId, vec);
				});

		return excludeBlockIds ?
				vecsByHashId.map(hashAndVecTuple -> hashAndVecTuple._2) :
				joinVecInfosToVecEntries(vecsByHashId, rid, hashIds, vecInfosfilter);
	}

	private JavaRDD<VecEntry<T, K>> joinVecInfosToVecEntries(
			JavaPairRDD<Long, VecEntry<T, K>> vecsByHashId,
			long rid, HashSet<Long> hashIds, Function<List<T>, List<T>> vecInfosfilter) {

		JavaPairRDD<Long, Iterable<String>> vecInfosByHashId = javaFunctions(sparkInstance.getContext())
				.cassandraTable(databaseName, _ADAPTIVE_HASH_VEC)
				.select(_HASHID_COLUMN, _VEC_INFO_COLUMN)
				.where(_APP_ID_COLUMN + " = ? AND " + _HASHID_COLUMN + " in ?", rid, hashIds)
				.mapToPair(row -> new Tuple2<>(row.getLong(0), row.getString(1)))
				.groupByKey();

		return vecsByHashId.join(vecInfosByHashId)
				.map(hashAndMatchTuple -> {
					VecEntry<T, K> vec = hashAndMatchTuple._2._1;
					Iterable<String> vecInfosAsStrings = hashAndMatchTuple._2._2;

					List<T> vecInfosFullList = new ArrayList<>();
					vecInfosAsStrings.forEach(text -> vecInfosFullList.add(VecInfo.<T>deSerialize(text)));
					if (vecInfosfilter != null) {
						vec.vids = new HashSet<T>(vecInfosfilter.apply(vecInfosFullList));
					} else {
						vec.vids = new HashSet<T>(vecInfosFullList);
					}

					return vec;
				});
	}

	public void dump(String file) {
		try {
			LineSequenceWriter writer = Lines.getLineWriter(file, false);
			javaFunctions(sparkInstance.getContext())
					.cassandraTable(databaseName, _ADAPTIVE_HASH)
					.select(_APP_ID_COLUMN, _HASHID_COLUMN, _IND_COLUMN, _FULLKEY_COLUMN)
					.map(CassandraRow::toString)
					.toLocalIterator().forEachRemaining(writer::writeLineNoExcept);

			javaFunctions(sparkInstance.getContext())
					.cassandraTable(databaseName, _ADAPTIVE_HASH_VEC)
					.select(_APP_ID_COLUMN, _HASHID_COLUMN, _VEC_INFO_COLUMN)
					.map(CassandraRow::toString)
					.toLocalIterator().forEachRemaining(writer::writeLineNoExcept);

			writer.close();
		} catch (Exception e) {
			logger.error("Failed to dump index.", e);
		}
	}

	@Override
	public void clear(long rid) {
		try {
			this.cassandraInstance.doWithSession(sess -> {
				if (isSingleUserApplication) {
					sess.execute(QueryBuilder.truncate(databaseName, _ADAPTIVE_HASH).build());
					sess.execute(QueryBuilder.truncate(databaseName, _ADAPTIVE_HASH_VEC).build());
				} else {
					sess.executeAsync(QueryBuilder.deleteFrom(databaseName, _ADAPTIVE_HASH).whereColumn(_APP_ID_COLUMN).isEqualTo(literal(rid)).build());
					sess.executeAsync(QueryBuilder.deleteFrom(databaseName, _ADAPTIVE_HASH_VEC).whereColumn(_APP_ID_COLUMN).isEqualTo(literal(rid)).build());
				}
			});
		} catch (Exception e) {
			logger.error("Failed to delete the index.", e);
		}
	}

}
