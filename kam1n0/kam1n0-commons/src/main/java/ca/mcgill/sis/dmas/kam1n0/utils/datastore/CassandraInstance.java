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
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import com.codahale.metrics.Gauge;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.WindowsFailedSnapshotTracker;
import org.apache.cassandra.metrics.CassandraMetricsRegistry;
import org.apache.cassandra.service.CassandraDaemon;
import org.apache.cassandra.thrift.Cassandra;
import org.apache.spark.SparkConf;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
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

import com.datastax.driver.core.*;
import com.datastax.spark.connector.cql.CassandraConnector;
import com.datastax.spark.connector.cql.SessionProxy;

public class CassandraInstance {

	private Logger logger = LoggerFactory.getLogger(CassandraInstance.class);

	public static final int DEFAULT_PORT = 9042;
	public static final int DEFAULT_STORAGE_PORT = 7000;

	public static final int maxWaitForNewCompactionTasksToStartMs = 5000;
	public static final int compactionTaskStatusPollingInterval = 1000;

	public int port = DEFAULT_PORT;
	public int port_storage = DEFAULT_STORAGE_PORT;
	public String clusterName = StringResources.STR_EMPTY;
	public String host = "127.0.0.1";

	public SparkInstance spark;

	public void setSparkInstance(SparkInstance spark) {
		this.spark = spark;
		this.doWithCluster(this.spark.getConf(), cluster -> {
			cluster.getConfiguration().getPoolingOptions().setMaxQueueSize(2048);
		});
	}

	private boolean inMem = false;

	public boolean isInMem() {
		return this.inMem;
	}

	public boolean isEmbedded() {
		return this.isEmbedded;
	}

	public List<Tuple2<String, String>> getSparkConfiguration() {
		return Arrays.asList(new Tuple2<String, String>("spark.cassandra.connection.host", host),
				new Tuple2<String, String>("spark.cassandra.connection.port", Integer.toString(port)),
				new Tuple2<String, String>("spark.cassandra.auth.username", "cassandra"),
				new Tuple2<String, String>("spark.cassandra.auth.password", "cassandra"));
	}

	private final ExecutorService service = Executors.newSingleThreadExecutor(
			new ThreadFactoryBuilder().setDaemon(true).setNameFormat("EmbeddedCassandra-%d").build());
	private CassandraDaemon cassandra = null;
	private File dataDir = null;
	private boolean isEmbedded = true;

	public static CassandraInstance createEmbeddedInstance(String clusterName, int port, int port_storage,
			boolean temporary, boolean inMemory) {
		if (inMemory) {
			CassandraInstance instance = new CassandraInstance();
			return instance;
		}
		CassandraInstance instance = new CassandraInstance(port, port_storage, clusterName, temporary);
		instance.isEmbedded = true;
		return instance;
	}

	public static CassandraInstance createEmbeddedInstance(String clusterName, boolean temporary, boolean inMemory) {
		if (inMemory) {
			CassandraInstance instance = new CassandraInstance();
			return instance;
		}
		CassandraInstance instance = new CassandraInstance(DEFAULT_PORT, DEFAULT_STORAGE_PORT, clusterName, temporary);
		instance.isEmbedded = true;
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
			System.setProperty("hadoop.home.dir", new File(KamResourceLoader.jPath + "/hadoop/").getAbsolutePath());
			System.setProperty("cassandra.config", "file:" + configFile.getPath());
			System.setProperty("cassandra.jmx.local.port", "7199");
			System.setProperty("cassandra.jmx.local.port", "7199");
			System.setProperty("CASSANDRA_HOME", KamResourceLoader.jPath);

			// create trigger directory for cassandra
			File triggerDir = new File(dataDir + "/Database_triggers/");
			triggerDir.mkdir();
			System.setProperty("cassandra.triggers_dir", triggerDir.getAbsolutePath());

			// need to change the path of snapshot. (original value does not work with
			// embedded instance on windows)
			Field toDeleteFileField = WindowsFailedSnapshotTracker.class.getField("TODELETEFILE");
			Field modifiersField = Field.class.getDeclaredField("modifiers");
			boolean origin = modifiersField.isAccessible();
			modifiersField.setAccessible(true);
			modifiersField.setInt(toDeleteFileField, toDeleteFileField.getModifiers() & ~Modifier.FINAL);
			toDeleteFileField.set(null, java.nio.file.Files.createTempFile("kam1n0-cassandra-tmp", ".ToDeleteFiles")
					.toFile().getAbsolutePath());
			modifiersField.setInt(toDeleteFileField, toDeleteFileField.getModifiers() & Modifier.FINAL);
			modifiersField.setAccessible(origin);

		} catch (Exception e) {
			logger.error("Failed to initialize the deamon. ", e);
		}
	}

	public Cassandra.Client getClient() throws TTransportException {
		TTransport tr = new TSocket(host, port);
		TProtocol proto = new TBinaryProtocol(tr);
		Cassandra.Client client = new Cassandra.Client(proto);
		tr.open();
		return client;
	}

	public void doWithCluster(SparkConf conf, DoWithObj<Cluster> func) {
		doWithSession(conf, session -> {
			func.doWith(session.getCluster());
		});
	}

	public <K> K doWithClusterWithReturn(SparkConf conf, DoWithObjHasReturn<Cluster, K> func) {
		return doWithSessionWithReturn(conf, session -> {
			return func.doWith(session.getCluster());
		});
	}

	public void doWithSession(SparkConf conf, DoWithObj<Session> func) {
		try (Session session = SessionProxy.wrap( //
				CassandraConnector //
						.apply(conf) //
						.openSession())) {
			func.doWith(session);
		}
	}

	public void doWithSession(DoWithObj<Session> func) {
		try (Session session = SessionProxy.wrap( //
				CassandraConnector //
						.apply(spark.getConf()) //
						.openSession())) {
			func.doWith(session);
		}
	}

	public <K> K doWithSessionWithReturn(SparkConf conf, DoWithObjHasReturn<Session, K> func) {
		try (Session session = SessionProxy.wrap( //
				CassandraConnector //
						.apply(conf) //
						.openSession())) {
			return func.doWith(session);
		}
	}

	public <K> K doWithSessionWithReturn(DoWithObjHasReturn<Session, K> func) {
		try (Session session = SessionProxy.wrap( //
				CassandraConnector //
						.apply(spark.getConf()) //
						.openSession())) {
			return func.doWith(session);
		}
	}

	public boolean checkColumnFamilies(SparkConf conf, String dbName, String... clmFamilyNames) {
		final Switch swt = new Switch(false);
		doWithCluster(conf, cluster -> {
			KeyspaceMetadata keysapce = cluster.getMetadata().getKeyspace(dbName);
			if (keysapce == null) {
				swt.value = false;
				return;
			}
			for (String name : clmFamilyNames) {
				if (keysapce.getTable(name) == null) {
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

				int remainingGracePeriodAfterLastCompaction = maxWaitForNewCompactionTasksToStartMs;
				if ( remainingTasks.isEmpty() ) {
					logger.info("Waiting at most {} seconds for potential compaction tasks to be triggered",
							maxWaitForNewCompactionTasksToStartMs / 1000.0);
				}

				while (!remainingTasks.isEmpty() || remainingGracePeriodAfterLastCompaction >= 0) {

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
									maxWaitForNewCompactionTasksToStartMs / 1000.0);
							remainingGracePeriodAfterLastCompaction = maxWaitForNewCompactionTasksToStartMs;
						}
					} else if (remainingTasks.isEmpty()) {
						remainingGracePeriodAfterLastCompaction -= compactionTaskStatusPollingInterval;
					}

					try {
						Thread.sleep(compactionTaskStatusPollingInterval);
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
			Future<Object> future = service.submit(new Callable<Object>() {
				@Override
				public Object call() throws Exception {
					try {
						DatabaseDescriptor.daemonInitialization();
						boolean runManaged = false;
						cassandra = new CassandraDaemon(runManaged);
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
				}
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
				Cluster cluster = Cluster.builder().addContactPoints(host).withPort(port).build();
				Session session = cluster.connect();
				session.execute("SELECT now() FROM system.local;");
				session.close();
				cluster.close();
				logger.info("Connection health checked.");
			} catch (Exception e) {
				logger.error("Failed to connect to the specified cassandra cluster.", e);
			}
		}
	}

	public boolean close() {
		if (inMem)
			return true;
		if (isEmbedded) {
			try {
				logger.info("Shutting down embedded Cassandra.");
				this.waitForCompactionTasksCompletion();
				service.shutdown();
				cassandra.stop();
				cassandra.deactivate();
				return true;
			} catch (Exception e) {
				logger.error("error closing database", e);
			}
			return false;
		}
		return true;
	}

	public static void main(String[] args) {
		Environment.init();

		CassandraInstance instance = CassandraInstance.createEmbeddedInstance("test", false, false);

		instance.init();

		instance.close();
	}

}
