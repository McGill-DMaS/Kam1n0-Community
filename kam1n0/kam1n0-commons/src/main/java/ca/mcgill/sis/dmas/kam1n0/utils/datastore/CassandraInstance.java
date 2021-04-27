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
package ca.mcgill.sis.dmas.kam1n0.utils.datastore;

import java.io.File;
import java.io.IOException;

import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.*;

import com.codahale.metrics.Gauge;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.WindowsFailedSnapshotTracker;
import org.apache.cassandra.metrics.CassandraMetricsRegistry;
import org.apache.cassandra.service.CassandraDaemon;
import org.apache.spark.SparkConf;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.metadata.schema.KeyspaceMetadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import scala.Tuple2;

import com.google.common.base.Preconditions;
import com.google.common.io.Files;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.ThreadFactoryBuilder;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.Switch;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

import com.datastax.spark.connector.cql.CassandraConnector;
import com.datastax.spark.connector.cql.SessionProxy;

public class CassandraInstance {
	private Logger logger = LoggerFactory.getLogger(CassandraInstance.class);

	public static final int DEFAULT_PORT = 9042;
	public static final int DEFAULT_STORAGE_PORT = 7000;

	public static final int maxWaitForNewCompactionTasksToStartInMs = 5000;
	public static final int compactionStatusPollingIntervalInMs = 1000;

	public int port = DEFAULT_PORT;
	public int port_storage = DEFAULT_STORAGE_PORT;
	public String clusterName = StringResources.STR_EMPTY;
	public String host = "127.0.0.1";

	public SparkInstance spark;

	public void setSparkInstance(SparkInstance spark) {
		this.spark = spark;
	}

	private boolean inMem = false;

	public boolean isInMem() {
		return this.inMem;
	}

	public boolean isEmbedded() {
		return this.isEmbedded;
	}

	public List<Tuple2<String, String>> getSparkConfiguration() {
		return Arrays.asList(new Tuple2<>("spark.cassandra.connection.host", host),
				new Tuple2<>("spark.cassandra.connection.port", Integer.toString(port)),
				new Tuple2<>("spark.cassandra.auth.username", "cassandra"),
				new Tuple2<>("spark.cassandra.auth.password", "cassandra"));
	}

	public CqlSessionBuilder getSessionBuilder(){
		return CqlSession.builder().addContactPoint(new InetSocketAddress(host, port));
	}

	private final ExecutorService service = Executors.newSingleThreadExecutor(
			new ThreadFactoryBuilder().setDaemon(true).setNameFormat("EmbeddedCassandra-%d").build());
	private CassandraDaemon cassandra = null;
	private boolean isEmbedded = true;

	public static CassandraInstance createEmbeddedInstance(String clusterName, int port, int port_storage,
			boolean temporary, boolean inMemory) {
		CassandraInstance instance;
		if (inMemory) {
			instance = new CassandraInstance();
		} else {
			instance = new CassandraInstance(port, port_storage, clusterName, temporary);
			instance.isEmbedded = true;
		}
		return instance;
	}


	public static CassandraInstance createEmbeddedInstance(String clusterName, boolean temporary, boolean inMemory) {
		CassandraInstance instance;
		if (inMemory) {
			instance = new CassandraInstance();
		} else {
			instance = new CassandraInstance(DEFAULT_PORT, DEFAULT_STORAGE_PORT, clusterName, temporary);
			instance.isEmbedded = true;
		}
		return instance;
	}

	public static CassandraInstance createRemoteInstance(String host, int port) {
		CassandraInstance instance = new CassandraInstance(host, port);
		instance.isEmbedded = false;
		return instance;
	}

	public static CassandraInstance createRemoteInstance(String host) {
		CassandraInstance instance = new CassandraInstance(host, DEFAULT_PORT);
		instance.isEmbedded = false;
		return instance;
	}

	private CassandraInstance() {
		this.inMem = true;
	}

	private CassandraInstance(String host, int port) {
		this.host = host;
		this.port = port;
	}

	private CassandraInstance(int port, int port_storage, String clusterName, boolean temporary) {
		this.clusterName = clusterName;
		this.port = port;
		this.port_storage = port_storage;
		File dataDir = null;
		if (!temporary) {
			dataDir = new File(DmasApplication.applyDataContext("Database"));
			if (!dataDir.exists()) {
				dataDir.mkdirs();
			}
		} else {
			dataDir = DmasApplication.createTmpFolder("TmpDatabase" + StringResources.timeString());
		}
		try {
			java.net.URL templateUrl = CassandraInstance.class.getClassLoader().getResource("cassandra-template.yaml");
			Preconditions.checkNotNull(templateUrl, "Cassandra config template is null");
			String baseFile = Resources.toString(templateUrl, Charset.defaultCharset());

			String newFile = baseFile.replace("$DIR$", dataDir.getPath());
			newFile = newFile.replace("$PORT$", Integer.toString(port));
			newFile = newFile.replace("$STORAGE_PORT$", Integer.toString(port_storage));
			newFile = newFile.replace("$CLUSTER$", clusterName);

			File configFile = new File(dataDir, "cassandra.yaml");
			Files.write(newFile, configFile, Charset.defaultCharset());

			logger.info("Cassandra config file: " + configFile.getPath());
			System.setProperty("cassandra.storagedir", dataDir.getPath());
			File f = new File(KamResourceLoader.jPath + "/hadoop/");
			System.setProperty("hadoop.home.dir", f.getAbsolutePath());
			System.setProperty("cassandra.config", "file:" + configFile.getPath());
			System.setProperty("cassandra.jmx.local.port", "7199");
			System.setProperty("cassandra.jmx.local.port", "7199");
			System.setProperty("CASSANDRA_HOME", KamResourceLoader.jPath);

			// create trigger directory for cassandra
			File triggerDir = new File(dataDir + "/Database_triggers/");
			triggerDir.mkdir();
			System.setProperty("cassandra.triggers_dir", triggerDir.getAbsolutePath());

		} catch (Exception e) {
			logger.error("Failed to initialize the deamon. ", e);
		}
	}


	public void doWithSession(SparkConf conf, DoWithObj<CqlSession> func) {
		try (CqlSession session = SessionProxy.wrapWithCloseAction(
				CassandraConnector //
						.apply(conf) //
						.openSession(),v1 -> {return "";} )) {
			func.doWith(session);
		}
	}

	public void doWithSession(DoWithObj<CqlSession> func) {


		try (CqlSession session = SessionProxy.wrapWithCloseAction( //
				CassandraConnector //
						.apply(spark.getConf()) //
						.openSession(),v1 -> {return "";})) {
			func.doWith(session);
		}
	}

	public <K> K doWithSessionWithReturn(SparkConf conf, DoWithObjHasReturn<CqlSession, K> func) {
		try (CqlSession session = SessionProxy.wrapWithCloseAction( //
				CassandraConnector //
						.apply(conf) //
						.openSession(),v1 -> {return "";})) {
			return func.doWith(session);
		}
	}

	public <K> K doWithSessionWithReturn(DoWithObjHasReturn<CqlSession, K> func) {
		try (CqlSession session = SessionProxy.wrapWithCloseAction( //
				CassandraConnector //
						.apply(spark.getConf()) //
						.openSession(),v1 -> {return "";})) {
			return func.doWith(session);
		}
	}


	public boolean checkColumnFamilies(SparkConf conf, String dbName, String... clmFamilyNames) {
		final Switch swt = new Switch(false);
		doWithSession(conf, session -> {
			KeyspaceMetadata keyspace;

			if (session.getMetadata().getKeyspace(dbName).isPresent()){
				keyspace = session.getMetadata().getKeyspace(dbName).get();
			} else {
				swt.value = false;
				return;
			}

			for (String name : clmFamilyNames) {
				if (keyspace.getTable(name).isEmpty()) {
					swt.value = false;
					return;
				}
			}
			swt.value = true;
		});
		return swt.value;
	}

	/**
	 * Polls cassandra metrics until there are no more pending compaction tasks. Also, it logs the list of tables with
	 * pending/running compaction tasks everytime that list changes (i.e when one or more tasks are completed or
	 * added). This is only for an embedded Cassandra. In memory or on a distributed cluster, this returns immediately.
	 */
	public void waitForCompactionTasksCompletion() {
		if (isEmbedded) {
			@SuppressWarnings("unchecked")
			Gauge<Map<String, Map<String, Integer>>> gauge =
					CassandraMetricsRegistry.Metrics.getGauges().get("org.apache.cassandra.metrics.Compaction.PendingTasksByTableName");

			if (gauge != null) {
				Map<String, Map<String, Integer>> remainingTasks = gauge.getValue();
				Map<String, Map<String, Integer>> previousTasks = new HashMap<>();

				int remainingGracePeriodAfterLastCompaction = maxWaitForNewCompactionTasksToStartInMs;
				if ( remainingTasks.isEmpty() ) {
					logger.info("Waiting at most {} seconds for potential compaction tasks to be triggered",
							maxWaitForNewCompactionTasksToStartInMs / 1000.0);
				}

				while (!remainingTasks.isEmpty() || remainingGracePeriodAfterLastCompaction > 0) {

					if (!remainingTasks.equals(previousTasks)) {
						previousTasks.clear();
						if ( !remainingTasks.isEmpty() ) {
							logger.info("Waiting for compaction tasks to finish on following tables:");
							for (Map.Entry<String, Map<String, Integer>> keyspaceTasks : remainingTasks.entrySet()) {
								for (Map.Entry<String, Integer> tableTasks : keyspaceTasks.getValue().entrySet()) {
									String fullTableName = keyspaceTasks.getKey() + "." + tableTasks.getKey();
									logger.info("    {}: {}", fullTableName, tableTasks.getValue());
								}
								previousTasks.put(keyspaceTasks.getKey(), new HashMap<>(keyspaceTasks.getValue()));
							}
						} else {
							logger.info("Compaction tasks completed. Now waiting at most {} seconds for additional compaction tasks to be triggered",
									maxWaitForNewCompactionTasksToStartInMs / 1000.0);
							remainingGracePeriodAfterLastCompaction = maxWaitForNewCompactionTasksToStartInMs;
						}
					} else if (remainingTasks.isEmpty()) {
						remainingGracePeriodAfterLastCompaction -= compactionStatusPollingIntervalInMs;
					}

					try {
						Thread.sleep(compactionStatusPollingIntervalInMs);
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
					remainingTasks = gauge.getValue();
				}

				logger.info("Done with database compaction.");
			}
		}
	}

	public void init() {
		if (inMem)
			return;
		if (isEmbedded) {
			logger.info("Starting embedded cassandra instance...");
			Future<Object> future = service.submit(() -> {
				try {
					DatabaseDescriptor.daemonInitialization();
					boolean runManaged = false;
					cassandra = new CassandraDaemon(runManaged);
					com.sun.jna.NativeLibrary.getInstance("kernel32", Collections.emptyMap());
					cassandra.init(null);
				} catch (IOException e) {
					logger.error("Error initializing embedded cassandra", e);
					throw e;
				}
				try {
					cassandra.start();
				} catch (Exception e) {
					logger.error("Error initializing embedded cassandra", e);
				}
				return null;
			});

			try {
				future.get();
			} catch (Exception e) {
				logger.error("Error starting embedded cassandra", e);
				throw new RuntimeException(e);
			}
		} else {
			logger.info("Testing remote cassandra connection");
			try {
				CqlSession session = CqlSession.builder().addContactPoint(new InetSocketAddress(host, port)).build();
				session.execute("SELECT now() FROM system.local;");
				session.close();
				logger.info("Connection health checked.");
			} catch (Exception e) {
				logger.error("Failed to connect to the specified cassandra cluster.", e);
			}
		}

	}

	public boolean close() {
		boolean closed = true;
		if (isEmbedded) {
			try {
				logger.info("Shutting down embedded Cassandra.");
				this.waitForCompactionTasksCompletion();
				service.shutdown();
				cassandra.stop();
				cassandra.deactivate();
			} catch (Exception e) {
				logger.error("error closing database", e);
				closed = false;
			}
		}
		return closed;
	}

	public static void main(String[] args) {
		Environment.init();

		CassandraInstance instance = CassandraInstance.createEmbeddedInstance("test", false, false);

		instance.init();

		instance.close();
	}



}
