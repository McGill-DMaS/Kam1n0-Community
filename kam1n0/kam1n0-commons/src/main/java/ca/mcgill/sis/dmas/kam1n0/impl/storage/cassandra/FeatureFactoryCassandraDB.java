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

import static com.datastax.spark.connector.japi.CassandraJavaUtil.javaFunctions;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.datastax.oss.driver.api.core.cql.PreparedStatement;
import com.datastax.oss.driver.api.core.metadata.schema.KeyspaceMetadata;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.FeatureVecFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.FeatureVec;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class FeatureFactoryCassandraDB extends FeatureVecFactory {

	private static Logger logger = LoggerFactory.getLogger(FeatureFactoryCassandraDB.class);

	private CassandraInstance instance;
	private SparkInstance spark_Instance;
	private String databaseName;

	public static final String _VEC_B = "FEAT".toLowerCase();
	public static final String _VEC_B_KEY = "key";
	public static final String _VEC_B_VEC = "vector";
	private Map<String, String> nameMap = new java.util.HashMap<>();

	public FeatureFactoryCassandraDB(CassandraInstance instance, SparkInstance sparkInstance, String databaseName) {
		this.instance = instance;
		this.spark_Instance = sparkInstance;
		this.databaseName = databaseName;
	}

	@Override
	public void init() {
		instance.doWithSession(spark_Instance.getConf(), session -> {
			KeyspaceMetadata keysapce = session.getMetadata().getKeyspace(databaseName).get();

			if (keysapce == null || keysapce.getTable(databaseName) == null) {

				logger.info("Creating table: {}.{}", databaseName, _VEC_B);

				session.execute("CREATE KEYSPACE IF NOT EXISTS " + databaseName + " WITH "
						+ "replication = {'class':'SimpleStrategy', 'replication_factor':1} "
						+ " AND durable_writes = true;");

				session.execute("create table if not exists " + databaseName + "." + _VEC_B + " (" //
						+ _VEC_B_KEY + " bigint primary key," //
						+ _VEC_B_VEC + " blob," //
						+ ");");

			} else {
				logger.info("Found table: {}.{}", databaseName, _VEC_B);
			}
		});

		nameMap.put("_1", "key");
		nameMap.put("_2", "vector");
	}

	@Override
	public boolean putVec(List<FeatureVec> vecs) {
		try {
			instance.doWithSession(spark_Instance.getConf(), session -> {
				for (FeatureVec vec : vecs) {
					PreparedStatement statement = session.prepare("INSERT INTO " + databaseName + "." + _VEC_B + " (" + _VEC_B_KEY + "," + _VEC_B_VEC
							+ ") VALUES (?, ?)");
					session.execute(statement.bind(vec.key, ByteBuffer.wrap(SerializationUtils.serialize(vec))));
				}
			});
			return true;
		} catch (Exception e) {
			logger.error("Failed to persist vectors.", e);
			return false;
		}
	}

	@Override
	public List<FeatureVec> getVecs(Set<Long> keys) {
		return instance.doWithSessionWithReturn(spark_Instance.getConf(), session -> {
			PreparedStatement statement = session.prepare("SELECT " + _VEC_B_VEC + " FROM " + databaseName + "." + _VEC_B + " WHERE " + _VEC_B_KEY + " IN ?");
			return session.execute( statement.bind(keys)).all().stream().map(row -> {
				ByteBuffer data = row.getByteBuffer(0);
				byte[] result = new byte[data.remaining()];
				data.get(result);
				FeatureVec vec = SerializationUtils.deserialize(result);
				return vec;
			}).collect(Collectors.toList());
		});
	}

	@Override
	public JavaRDD<FeatureVec> getVecsAsRDD(Set<Long> keys) {
		return javaFunctions(this.spark_Instance.getContext())//
				.cassandraTable(databaseName, _VEC_B)//
				.select(_VEC_B_VEC).where(_VEC_B_KEY + " in ? ", keys)//
				.map(row -> {
					ByteBuffer data = row.getBytes(0);
					byte[] result = new byte[data.remaining()];
					data.get(result);
					FeatureVec vec = SerializationUtils.deserialize(result);
					return vec;
				});
	}

	@Override
	public boolean dropVec(List<Long> keys) {
		try {
			instance.doWithSession(spark_Instance.getConf(), session -> {
				PreparedStatement statement = session.prepare("DELETE FROM " + databaseName + "." + _VEC_B + " where " + _VEC_B_KEY + " in ?");
				session.execute(statement.bind(keys));
			});
			return true;
		} catch (Exception e) {
			logger.error("Failed to drop the vectors.", e);
			return false;
		}
	}

	@Override
	public void close() {

	}

}
