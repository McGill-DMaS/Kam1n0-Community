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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.datastax.driver.core.BatchStatement;
import com.datastax.driver.core.PreparedStatement;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.querybuilder.*;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketHierarchy;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketHierarchyIndex;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class BucketHierarchyTrackerCassandraDB extends BucketHierarchyIndex {

	private static Logger logger = LoggerFactory.getLogger(BucketHierarchyTrackerCassandraDB.class);

	private CassandraInstance cassandraInstance;
	private SparkInstance sparkInstance;
	public String databaseName = StringResources.STR_EMPTY;

	// classes:
	public static final String _BUCKETHIE = "BUCKETHIE".toLowerCase();
	public static final String _BUCKETDEPT = "BUCKETDEP".toLowerCase();

	// properties:
	public static final String _BUCKETHIE_PARENT_ID = "parent";
	public static final String _BUCKETHIE_CHILDREN = "children";
	public static final String _BUCKETDEPT_PATH = "path";
	public static final String _BUCKETDEPT_DEPTH = "depth";

	private static String STATE_SELECT = StringResources.STR_EMPTY;
	private static String STATE_SELECT_P_C_L1 = StringResources.STR_EMPTY;
	private static String STATE_SELECT_P_C_R1 = StringResources.STR_EMPTY;
	private static String STATE_INSERT = StringResources.STR_EMPTY;
	private static String STATE_DEL_P = StringResources.STR_EMPTY;
	private static String STATE_DEL_P_C = StringResources.STR_EMPTY;

	public BucketHierarchyTrackerCassandraDB(CassandraInstance cassandraInstance, SparkInstance sparkInstance,
			String databaseName) {
		this.cassandraInstance = cassandraInstance;
		this.sparkInstance = sparkInstance;
		this.databaseName = databaseName;

		STATE_INSERT = "INSERT INTO " + databaseName + "." + _BUCKETHIE + " VALUES(?,?)";

		STATE_SELECT = "SELECT " + _BUCKETHIE_CHILDREN + " FROM " + databaseName + "." + _BUCKETHIE + " WHERE "
				+ _BUCKETHIE_PARENT_ID + " = ?";

		STATE_SELECT_P_C_L1 = "SELECT " + _BUCKETHIE_CHILDREN + " FROM " + databaseName + "." + _BUCKETHIE + " WHERE "
				+ _BUCKETHIE_PARENT_ID + " = ? AND " + _BUCKETHIE_CHILDREN + " < ? LIMIT 1";

		STATE_SELECT_P_C_R1 = "SELECT " + _BUCKETHIE_CHILDREN + " FROM " + databaseName + "." + _BUCKETHIE + " WHERE "
				+ _BUCKETHIE_PARENT_ID + " = ? AND " + _BUCKETHIE_CHILDREN + " > ? LIMIT 1";

		STATE_DEL_P = "DELETE FROM " + databaseName + "." + _BUCKETHIE + " where " + _BUCKETHIE_PARENT_ID + " = ?";

		STATE_DEL_P_C = "DELETE FROM " + databaseName + "." + _BUCKETHIE + " where " + _BUCKETHIE_PARENT_ID
				+ " = ? AND " + _BUCKETHIE_CHILDREN + " = ?";
	}

	public void createSchema() {

		if (!cassandraInstance.checkColumnFamilies(sparkInstance.getConf(), databaseName, _BUCKETHIE)) {
			logger.info("Creating table: {}.{}", databaseName, _BUCKETHIE);
			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				session.execute("CREATE KEYSPACE IF NOT EXISTS " + databaseName + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");

				// parent as partition key
				// children id as clustering key

				session.execute("create table if not exists " + databaseName + "." + _BUCKETHIE + " (" //
						+ _BUCKETHIE_PARENT_ID + " varchar," //
						+ _BUCKETHIE_CHILDREN + " varchar," //
						+ "PRIMARY KEY ((" + _BUCKETHIE_PARENT_ID + "), " + _BUCKETHIE_CHILDREN + ")" //
						+ ");");

				session.execute("create table if not exists " + databaseName + "." + _BUCKETDEPT + " (" //
						+ _BUCKETDEPT_PATH + " varchar," //
						+ _BUCKETDEPT_DEPTH + " int," //
						+ "PRIMARY KEY (" + _BUCKETDEPT_PATH + ")" + ");");

			});
		} else {
			logger.info("Found table: {}.{}", databaseName, _BUCKETHIE);
		}
	}

	@Override
	public void init() {
		createSchema();
	}

	@Override
	public boolean close() {
		// nothing to clean
		return true;
	}

	@Override
	public boolean put(String parentBkt, String... childBkts) {
		try {

			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				for (String child : childBkts) {
					session.execute(STATE_INSERT, parentBkt, child);
				}
			});
			return true;
		} catch (Exception e) {
			logger.info("Fiailed to persist bucket relationship.", e);
			return false;
		}
	}

	@Override
	public boolean put(BucketHierarchy relt) {
		try {
			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				PreparedStatement statement = session.prepare(STATE_INSERT);
				BatchStatement batch = new BatchStatement();
				for (String child : relt.children) {
					batch.add(statement.bind(relt.parent, child));
				}
				session.execute(batch);
			});
			return true;
		} catch (Exception e) {
			logger.info("Fiailed to persist bucket relationship.", e);
			return false;
		}
	}

	@Override
	public boolean put(List<BucketHierarchy> relts) {
		int sum = relts.stream().mapToInt(relt -> (put(relt) ? 0 : 1)).sum();
		return sum == 0;
	}

	@Override
	public boolean drop(String parentBkt) {
		try {
			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				PreparedStatement statement = session.prepare(STATE_DEL_P);
				session.execute(statement.bind(parentBkt));
			});
			return true;
		} catch (Exception e) {
			logger.info("Fiailed to remove bucket relationship for " + parentBkt, e);
			return false;
		}
	}

	@Override
	public boolean drop(String parentBkt, String childBkt) {
		try {
			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				PreparedStatement statement = session.prepare(STATE_DEL_P_C);
				session.execute(statement.bind(parentBkt, childBkt));
			});
			return true;
		} catch (Exception e) {
			logger.info("Fiailed to remove bucket relationship for " + parentBkt, e);
			return false;
		}
	}

	@Override
	public BucketHierarchy get(String parentBkt) {
		try {
			final BucketHierarchy hie = new BucketHierarchy();
			cassandraInstance.doWithSession(sparkInstance.getConf(), session -> {
				PreparedStatement statement = session.prepare(STATE_SELECT);
				ResultSet rslt = session.execute(statement.bind(parentBkt));
				hie.parent = parentBkt;
				rslt.forEach(row -> hie.children.add(row.getString(0)));
			});
			return hie;
		} catch (Exception e) {
			logger.info("Fiailed to remove bucket relationship for " + parentBkt, e);
			return null;
		}
	}

	@Override
	public String nextOnTheLeft(String parentBkt, String chilBkt) {
		try {
			return cassandraInstance.doWithSessionWithReturn(sparkInstance.getConf(), session -> {
				PreparedStatement statement = session.prepare(STATE_SELECT_P_C_L1);
				ResultSet rslt = session.execute(statement.bind(parentBkt));
				if (rslt == null) {
					return null;
				} else {
					List<Row> all = rslt.all();
					if (all.size() == 0)
						return null;
					else
						return all.get(0).getString(0);
				}
			});
		} catch (Exception e) {
			logger.info("Fiailed to remove bucket relationship for " + parentBkt, e);
			return null;
		}
	}

	@Override
	public String nextOnTheRight(String parentBkt, String chilBk) {
		try {
			return cassandraInstance.doWithSessionWithReturn(sparkInstance.getConf(), session -> {
				PreparedStatement statement = session.prepare(STATE_SELECT_P_C_R1);
				ResultSet rslt = session.execute(statement.bind(parentBkt));
				if (rslt == null) {
					return null;
				} else {
					List<Row> all = rslt.all();
					if (all.size() == 0)
						return null;
					else
						return all.get(0).getString(0);
				}
			});
		} catch (Exception e) {
			logger.info("Fiailed to remove bucket relationship for " + parentBkt, e);
			return null;
		}
	}

	@Override
	public Integer getLeafDepth(String fullLength) {
		return cassandraInstance.doWithSessionWithReturn(this.sparkInstance.getConf(), session -> {
			Row row = session
					.execute(QueryBuilder
							.select(_BUCKETDEPT_DEPTH)//
							.from(databaseName, _BUCKETDEPT)//
							.where(QueryBuilder//
									.eq(_BUCKETDEPT_PATH, fullLength)))//
					.one();
			if (row == null)
				return null;
			else
				return row.getInt(0);
		});
	}

	@Override
	public boolean setLeafDepth(String fullPath, int depth) {
		cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
			session.execute(QueryBuilder
					.insertInto(databaseName, _BUCKETDEPT)//
					.value(_BUCKETDEPT_PATH, fullPath)//
					.value(_BUCKETDEPT_DEPTH, depth));
		});
		return true;
	}

	@Override
	public boolean removeDepth(String fullPath) {
		cassandraInstance.doWithSession(this.sparkInstance.getConf(), session -> {
			session.execute(QueryBuilder
					.delete()//
					.from(databaseName, _BUCKETDEPT)//
					.where(QueryBuilder//
							.eq(_BUCKETDEPT_PATH, fullPath)));
		});
		return true;
	}

}
