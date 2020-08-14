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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Collectors;

import com.datastax.oss.driver.api.core.cql.Row;
import com.datastax.oss.driver.api.querybuilder.QueryBuilder;
import org.apache.commons.lang.NotImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

import static com.datastax.oss.driver.api.querybuilder.QueryBuilder.literal;

public class DifferentialIndexCassandra extends DifferentialIndexAbstract {

	private static Logger logger = LoggerFactory.getLogger(DifferentialIndexCassandra.class);
	private SparkInstance sparkInstance;
	private CassandraInstance cassandraInstance;
	private String databaseName = StringResources.STR_EMPTY;

	// public HashMap<Long, HashMap<String, IOBucketCtn>> data = new
	// HashMap<>();
	// public HashMap<Integer, IOSymHashCnt> hidTable = new HashMap<>();

	// classes:
	public static final String _REPO_PREFIX = "rid0".toLowerCase();
	public static final String _SYMBOLIC_DIFF = "diff".toLowerCase();
	public static final String _SYMBOLIC_DIFFC = "diff_count".toLowerCase();

	public static final String _SYMBOLIC_DIFFC_CT = "ct";

	// properties:
	public static final String _SYMBOLIC_DIFF_K1 = "pkey";
	public static final String _SYMBOLIC_DIFF_K2 = "ckey";

	public static final String _SYMBOLIC_DIFF_K1L = "lkey";
	public static final String _SYMBOLIC_DIFF_NVAL = "nval";
	public static final String _SYMBOLIC_DIFF_MAJR = "mjr";
	public static final String _SYMBOLIC_DIFF_CNT = "cnt";

	private static final String[] DIFF_META = new String[] { _SYMBOLIC_DIFF_K1L, _SYMBOLIC_DIFF_NVAL,
			_SYMBOLIC_DIFF_MAJR };
	private static final String[] DIFF_FULL = new String[] { _SYMBOLIC_DIFF_K1L, _SYMBOLIC_DIFF_NVAL,
			_SYMBOLIC_DIFF_MAJR, _SYMBOLIC_DIFF_CNT };

	private static final String[] DIFF_ALL = new String[] { _SYMBOLIC_DIFF_K1, _SYMBOLIC_DIFF_K2, _SYMBOLIC_DIFF_K1L,
			_SYMBOLIC_DIFF_NVAL, _SYMBOLIC_DIFF_MAJR, _SYMBOLIC_DIFF_CNT };

	public static final String _SYMBOLIC_HASH = "hidt".toLowerCase();

	public static final String _SYMBOLIC_HASH_HID = "hid";
	public static final String _SYMBOLIC_HASH_CNT = "cnt";

	private static final String[] HASH_FULL = new String[] { _SYMBOLIC_HASH_HID, _SYMBOLIC_HASH_CNT };

	public DifferentialIndexCassandra(SparkInstance sparkInstance, CassandraInstance cassandraInstance,
			String databaseName) {
		this.sparkInstance = sparkInstance;
		this.cassandraInstance = cassandraInstance;
		this.databaseName = databaseName;
	}

	@Override
	public void init() {
		this.createSchema();
	}

	private void createSchema() {
		if (!cassandraInstance.checkColumnFamilies(this.sparkInstance.getConf(), this.databaseName, _SYMBOLIC_DIFF)) {
			logger.info("Creating table {}.{}", databaseName, _SYMBOLIC_DIFF);
			this.cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
				session.execute("CREATE KEYSPACE if not exists " + databaseName + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");
				session.execute("create table if not exists " + databaseName + "." + _SYMBOLIC_DIFF + " (" //
						+ _REPO_PREFIX + " bigint," //
						+ _SYMBOLIC_DIFF_K1 + " bigint," //
						+ _SYMBOLIC_DIFF_K2 + " varchar," //
						+ _SYMBOLIC_DIFF_K1L + " bigint," //
						+ _SYMBOLIC_DIFF_NVAL + " bigint," //
						+ _SYMBOLIC_DIFF_MAJR + " bigint," //
				// + _SYMBOLIC_DIFF_CT + " counter," //
						+ _SYMBOLIC_DIFF_CNT + " list<blob>," //
						+ "PRIMARY KEY ((" + _REPO_PREFIX + "," + _SYMBOLIC_DIFF_K1 + "), " //
						+ _SYMBOLIC_DIFF_K2 + ")" //
						+ ");");

				session.execute("create table if not exists " + databaseName + "." + _SYMBOLIC_DIFFC + " (" //
						+ _REPO_PREFIX + " bigint," //
						+ _SYMBOLIC_DIFF_K1 + " bigint," //
						+ _SYMBOLIC_DIFF_K2 + " varchar," //
						+ _SYMBOLIC_DIFFC_CT + " counter," //
						+ "PRIMARY KEY ((" + _REPO_PREFIX + "," + _SYMBOLIC_DIFF_K1 + ")," + _SYMBOLIC_DIFF_K2 + ")" //
						+ ");");
			});
		} else {
			logger.info("Found table {}.{}", databaseName, _SYMBOLIC_DIFF);
		}

		if (!cassandraInstance.checkColumnFamilies(this.sparkInstance.getConf(), this.databaseName, _SYMBOLIC_HASH)) {
			logger.info("Creating table {}.{}", databaseName, _SYMBOLIC_HASH);
			this.cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
				session.execute("CREATE KEYSPACE if not exists " + databaseName + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");
				session.execute("create table if not exists " + databaseName + "." + _SYMBOLIC_HASH + " (" //
						+ _REPO_PREFIX + " bigint," //
						+ _SYMBOLIC_HASH_HID + " int," //
						+ _SYMBOLIC_HASH_CNT + " list<blob>," //
						+ "PRIMARY KEY ((" + _REPO_PREFIX + "," + _SYMBOLIC_HASH_HID + "))" //
						+ ");");
			});
		} else {
			logger.info("Found table {}.{}", databaseName, _SYMBOLIC_HASH);
		}

	}

	@Override
	public IOBucketCtn loadBucket(long rid, Long primaryKey, String secondaryKey) {
		IOBucketCtn bucket = this.cassandraInstance.doWithSessionWithReturn(this.sparkInstance.getConf(), session -> {
			Row row = session.execute((QueryBuilder.selectFrom(databaseName, _SYMBOLIC_DIFF)
							.columns(DIFF_FULL)//
							.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))//
							.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(primaryKey))
							.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(secondaryKey))
							.build())//
			).one();
			// not existed
			if (row == null)
				return null;

			Long k1l = row.isNull(0) ? null : row.getLong(0);
			Long nval = row.isNull(1) ? null : row.getLong(1);
			Long maj = row.isNull(2) ? null : row.getLong(2);

			List<ByteBuffer> cnts = row.getList(3, ByteBuffer.class);
			IOBucketCtn cnt = new IOBucketCtn(k1l, nval, maj, cnts.size());
			ObjectMapper mapper = new ObjectMapper();
			cnt.entries.addAll(cnts.stream().map(buff -> {
				try {

					return mapper.readValue(read(buff), IOSymHashMeta.class);
				} catch (Exception e) {
					logger.error("Failed to seralized bytebuffer for IOSymHashMeta. ", e);
					return null;
				}
			}).filter(val -> val != null).collect(Collectors.toList()));
			return cnt;
		});
		if (bucket != null)
			return bucket;
		return null;
	}

	@Override
	public boolean setBucket(long rid, Long K1, String val, IOBucketCtn cnt) {

		ObjectMapper mapper = new ObjectMapper();

		List<ByteBuffer> cnts = cnt.entries.stream().map(ct -> {
			try {
				return mapper.writeValueAsBytes(ct);
			} catch (JsonProcessingException e) {
				logger.error("Failed to serialize IOSymHashMeta", e);
				return null;
			}
		}).filter(bytes -> bytes != null).map(bytes -> ByteBuffer.wrap(bytes)).collect(Collectors.toList());

		this.cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
			session.executeAsync(QueryBuilder//
					.insertInto(databaseName, _SYMBOLIC_DIFF)//
					.value(_REPO_PREFIX, literal(rid)) //
					.value(_SYMBOLIC_DIFF_K1, literal(K1))//
					.value(_SYMBOLIC_DIFF_K2, literal(val))//
					.value(_SYMBOLIC_DIFF_K1L, literal(cnt.K1))//
					.value(_SYMBOLIC_DIFF_NVAL, literal(cnt.newVal))//
					.value(_SYMBOLIC_DIFF_MAJR, literal(cnt.majority))//
					.value(_SYMBOLIC_DIFF_CNT, literal(cnts)).build());

			session.executeAsync(QueryBuilder.update(databaseName, _SYMBOLIC_DIFFC)
					.increment(_SYMBOLIC_DIFFC_CT,literal(cnt.count))
					.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))
					.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(K1))
					.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(val))
					.build());

		});
		return true;
	}

	@Override
	public IOBucketMeta loadMeta(long rid, Long primaryKey, String secondaryKey) {
		IOBucketMeta bucket = this.cassandraInstance.doWithSessionWithReturn(this.sparkInstance.getConf(), session -> {
			Row row = session.execute((QueryBuilder//
					.selectFrom(databaseName, _SYMBOLIC_DIFF)
							.columns(DIFF_META))//
							.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))
							.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(primaryKey))
							.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(secondaryKey))
							.build())
					.one();

			Row crow = session.execute((QueryBuilder//
					.selectFrom(databaseName, _SYMBOLIC_DIFFC)
							.columns(_SYMBOLIC_DIFFC_CT))//

							.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))
							.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(primaryKey))
							.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(secondaryKey))
							.build())//
					.one();

			// not existed
			if (row == null)
				return null;
			// existed
			// if (row.isNull(0))
			// return null;

			long count = 0;
			if (crow != null && !crow.isNull(0))
				count = crow.getLong(0);

			Long k1l = row.isNull(0) ? null : row.getLong(0);
			Long nval = row.isNull(1) ? null : row.getLong(1);
			Long maj = row.isNull(2) ? null : row.getLong(2);

			IOBucketMeta cnt = new IOBucketMeta(k1l, nval, maj, (int) count);
			return cnt;
		});
		if (bucket != null)
			return bucket;
		return null;
	}

	@Override
	public void addHidToBucket(long rid, Long K1, String val, IOSymHashMeta hid) {

		try {
			byte[] cnt = new ObjectMapper().writeValueAsBytes(hid);

			if (cnt != null)
				this.cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
					session.executeAsync(//
							QueryBuilder//
									.update(databaseName, _SYMBOLIC_DIFF)//
									.appendListElement(_SYMBOLIC_DIFF_CNT, literal(ByteBuffer.wrap(cnt)))
									.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))
									.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(K1))
									.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(val))
									.build()
					);

					session.executeAsync(QueryBuilder.update(databaseName, _SYMBOLIC_DIFFC)
							.increment(_SYMBOLIC_DIFFC_CT)//
							.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))
							.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(K1))
							.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(val))
							.build());
				});
		} catch (JsonProcessingException e) {
			logger.error("Failed to add hid to {}::{}", K1, val);
		}

	}

	@Override
	public void addEntry(long rid, int hid, IOEntry entry) {
		try {
			byte[] cnt = new ObjectMapper().writeValueAsBytes(entry);

			if (cnt != null)
				this.cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
					session.executeAsync(//
							QueryBuilder//
									.update(databaseName, _SYMBOLIC_HASH)//
									.appendListElement(_SYMBOLIC_HASH_CNT,literal(ByteBuffer.wrap(cnt)))
									.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))//
									.whereColumn(_SYMBOLIC_HASH_HID).isEqualTo(literal(hid))
									.build()//
					);
				});
		} catch (JsonProcessingException e) {
			logger.error("Failed to add hid to {}", hid);
		}

	}

	@Override
	public boolean checkHid(long rid, int hid) {
		return this.cassandraInstance.doWithSessionWithReturn(sparkInstance.getConf(), session -> {
			Row row = session.execute(//
					QueryBuilder//
							.selectFrom(databaseName, _SYMBOLIC_HASH)
							.column(_SYMBOLIC_HASH_HID)//
							.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))//
							.whereColumn(_SYMBOLIC_HASH_HID).isEqualTo(literal(hid))
							.build()//
			).one();

			if (row == null || row.isNull(0))
				return false;
			return true;
		});
	}

	// public static final String _SYMBOLIC_HASH = "hidt".toLowerCase();
	// public static final String _SYMBOLIC_HASH_HID = "hid";
	// public static final String _SYMBOLIC_HASH_CT = "cnt";
	// public static final String _SYMBOLIC_HASH_CNT = "cnt";

	@Override
	public IOSymHashCnt loadHashCnt(long rid, int hid) {
		IOSymHashCnt bucket = this.cassandraInstance.doWithSessionWithReturn(this.sparkInstance.getConf(), session -> {
			Row row = session.execute(QueryBuilder//
							.selectFrom(databaseName, _SYMBOLIC_HASH)
							.columns(HASH_FULL)//
							.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))//
							.whereColumn(_SYMBOLIC_HASH_HID).isEqualTo(literal(hid))
							.build())
					.one();
			// not existed
			if (row == null)
				return null;
			// existed
			if (row.isNull(0))
				return null;

			IOSymHashCnt cnt = new IOSymHashCnt(row.getInt(0));
			List<ByteBuffer> cnts = row.getList(1, ByteBuffer.class);
			ObjectMapper mapper = new ObjectMapper();
			cnt.entries.addAll(cnts.parallelStream().map(buff -> {
				try {
					return mapper.readValue(read(buff), IOEntry.class);
				} catch (Exception e) {
					logger.error("Failed to seralized bytebuffer for IOEntry. ", e);
					return null;
				}
			}).filter(val -> val != null).collect(Collectors.toList()));
			return cnt;
		});
		if (bucket != null)
			return bucket;
		// logger.error("Find a null hash bucket for {}", hid);
		return null;
	}

	@Override
	public int loadHashCntCount(long rid, int hid) {
		throw new NotImplementedException();
	}

	// public static final String _SYMBOLIC_DIFF = "diff".toLowerCase();

	// public static final String _SYMBOLIC_DIFF_K1 = "pkey";
	// public static final String _SYMBOLIC_DIFF_K2 = "ckey";
	//
	// public static final String _SYMBOLIC_DIFF_K1L = "lkey";
	// public static final String _SYMBOLIC_DIFF_NVAL = "nval";
	// public static final String _SYMBOLIC_DIFF_MAJR = "mjr";
	// public static final String _SYMBOLIC_DIFF_CT = "ct";
	// public static final String _SYMBOLIC_DIFF_CNT = "cnt";

	@Override
	public boolean dump(String folder) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			{
				LineSequenceWriter writer = Lines.getLineWriter(folder + "//btable.txt", false);
				this.cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
					session.execute(QueryBuilder//
							.selectFrom(databaseName, _SYMBOLIC_DIFF)
							.columns(DIFF_ALL)//
							.build()).all().forEach(row -> {

								Long rid = row.isNull(0) ? null : row.getLong(0);
								Long k1 = row.isNull(1) ? null : row.getLong(1);
								String k2 = row.isNull(2) ? null : row.getString(2);
								Long k1l = row.isNull(3) ? null : row.getLong(3);
								Long nval = row.isNull(4) ? null : row.getLong(4);
								Long maj = row.isNull(5) ? null : row.getLong(5);

								Row crow = session.execute((QueryBuilder//
										.selectFrom(databaseName, _SYMBOLIC_DIFFC)
												.columns(_SYMBOLIC_DIFFC_CT))//
												.whereColumn(_REPO_PREFIX).isEqualTo(literal(rid))//
												.whereColumn(_SYMBOLIC_DIFF_K1).isEqualTo(literal(k1))//
												.whereColumn(_SYMBOLIC_DIFF_K2).isEqualTo(literal(k2))//
												.build())
										.one();
								Long count = crow.getLong(0);

								List<IOSymHashMeta> metas = row.getList(5, ByteBuffer.class).stream().map(buff -> {
									try {

										return mapper.readValue(read(buff), IOSymHashMeta.class);
									} catch (Exception e) {
										logger.error("Failed to seralized bytebuffer for IOSymHashMeta. ", e);
										return null;
									}
								}).filter(val -> val != null).collect(Collectors.toList());

								if (metas.size() == 0) {
									String str = StringResources.format("{}::{} -> K1:{} newVal:{} Maj:{} Cnt:{}/{}", //
											k1, //
											k2, //
											k1l, //
											nval, //
											maj, //
											count, metas.size());
									try {
										writer.writeLine(str);
									} catch (Exception e) {
										e.printStackTrace();
									}
								} else {
									metas.forEach(meta -> {
										String str = StringResources.format(
												"{}::{} -> K1:{} newVal:{} Maj:{} Cnt:{}/{} HID:{} VarName:{} IN:{} REP:{}", //
												k1, //
												k2, //
												k1l, //
												nval, //
												maj, //
												count, metas.size(), meta.hid, meta.varName, meta.input, meta.rep);
										try {
											writer.writeLine(str);
										} catch (Exception e) {
											e.printStackTrace();
										}
									});
								}

							});
				});
				writer.close();
			}
			{
				// public static final String _SYMBOLIC_HASH =
				// "hidt".toLowerCase();
				// public static final String _SYMBOLIC_HASH_HID = "hid";
				// public static final String _SYMBOLIC_HASH_CNT = "cnt";
				LineSequenceWriter writer = Lines.getLineWriter(folder + "//htable.txt", false);
				this.cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
					session.execute(QueryBuilder//
							.selectFrom(databaseName, _SYMBOLIC_HASH).columns(HASH_FULL)
							.build()).all().forEach(row -> {
								List<IOEntry> metas = row.getList(1, ByteBuffer.class).stream().map(buff -> {
									try {
										return mapper.readValue(read(buff), IOEntry.class);
									} catch (Exception e) {
										logger.error("Failed to seralized bytebuffer for IOSymHashMeta. ", e);
										return null;
									}
								}).filter(val -> val != null).collect(Collectors.toList());

								metas.forEach(meta -> {
									String str = StringResources.format(
											"{} -> Cnt:{} Fid:{} Bid:{} Var:{} Calls:{} funcSize:{}", //
											row.getInt(0), //
											metas.size(), //
											meta.functionId, meta.blockId, meta.varName, meta.calls, meta.funcSize);
									try {
										writer.writeLine(str);
									} catch (Exception e) {
										e.printStackTrace();
									}
								});

							});
				});
				writer.close();
			}

		} catch (Exception e) {
			logger.error("Failed to dump index.", e);
		}
		return true;
	}

	private static byte[] read(ByteBuffer buff) {
		byte[] bytes = new byte[buff.remaining()];
		buff.get(bytes);
		return bytes;
	}

}
