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
package ca.mcgill.sis.dmas.kam1n0.utils.executor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.OptionalLong;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.antlr.grammar.v3.ANTLRParser.option_return;
import org.apache.spark.SparkConf;
import org.apache.spark.SparkJobInfo;
import org.apache.spark.SparkStageInfo;
import org.apache.spark.SparkStatusTracker;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.api.java.JavaSparkStatusTracker;
import org.apache.spark.status.AppStatusStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.res.KamResourceLoader;
import scala.Option;
import scala.Tuple2;

public class SparkInstance {

	private static Logger logger = LoggerFactory.getLogger(SparkInstance.class);

	public int driverport = 7077;
	public String host = "localhost";
	public String rm_exc_mem = "2g";

	public boolean showWebUI = true;
	public int webUIPort = 4040;

	public int core_localMode = 2;
	public boolean localMode = true;
	public int timeout = 10;

	private JavaSparkContext context;
	private JavaSparkStatusTracker tracker;
	private List<Tuple2<String, String>> other_config = null;

	private ScheduledExecutorService scheduler;

	public SparkInstance() {
		this.localMode = true;
	}

	public static SparkInstance createRemoteInstance(String host, int port, boolean showWebUI, int webUIPort,
			String rmModeExcMem, List<Tuple2<String, String>> otherConfigs) {
		return new SparkInstance(host, port, showWebUI, webUIPort, rmModeExcMem, otherConfigs);
	}

	public static SparkInstance createRemoteInstance(String host, List<Tuple2<String, String>> otherConfigs) {
		return createRemoteInstance(host, 7077, true, 4040, "2g", otherConfigs);
	}

	private SparkInstance(String host, int driverport, boolean showWebUI, int webUIPort, String rmModeExcMem,
			List<Tuple2<String, String>> otherConfigs) {
		this.host = host;
		this.driverport = driverport;
		this.other_config = otherConfigs;
		this.localMode = false;
		this.showWebUI = showWebUI;
		this.webUIPort = webUIPort;
		this.rm_exc_mem = rmModeExcMem;
	}

	static SparkInstance internalInstance;

	public static SparkInstance createLocalInstance(List<Tuple2<String, String>> otherConfigs) {
		String core = System.getProperty("spark.local.cores", "4");
		String min = System.getProperty("spark.job.timeout.min", "10");
		String web = System.getProperty("spark.web", "true");
		SparkInstance spark = new SparkInstance(Integer.parseInt(core), Boolean.parseBoolean(web), 4040, otherConfigs);
		spark.timeout = Integer.parseInt(min);
		internalInstance = spark;
		return spark;
	}

	public static SparkInstance createLocalInstance() {
		return createLocalInstance(new ArrayList<>());
	}

	public static SparkInstance createLocalInstance(int cores, boolean showWebUI, int webUIPort,
			List<Tuple2<String, String>> otherConfigs) {
		return new SparkInstance(cores, showWebUI, webUIPort, otherConfigs);
	}

	private SparkInstance(int cores, boolean showWebUI, int webUIPort, List<Tuple2<String, String>> otherConfigs) {
		this.other_config = otherConfigs;
		this.localMode = true;
		this.showWebUI = showWebUI;
		this.webUIPort = webUIPort;
		this.core_localMode = cores;
	}

	public SparkConf getConf() {
		SparkConf conf = new SparkConf();
		if (localMode) {
			String cores = this.core_localMode > 0 ? Integer.toString(this.core_localMode) : "*";
			conf.setMaster("local[" + cores + "]");
			conf.set("spark.driver.host", "127.0.0.1");
			conf.set("spark.ui.enabled", Boolean.toString(showWebUI));
			conf.set("spark.ui.port", Integer.toString(webUIPort));
			conf.setAppName("Kam1n0-Spark");
			// conf.set("spark.scheduler.mode", "FIFO");
			conf.set("spark.ui.showConsoleProgress", "false");
			conf.set("spark.driver.maxResultSize", "4G");
			// conf.set("spark.scheduler.minRegisteredResourcesRatio", "0.5");
		} else {
			conf.setMaster("spark://" + host + ":" + driverport);
			conf.setAppName("Kam1n0-Spark");
			conf.set("spark.ui.enabled", Boolean.toString(showWebUI));
			conf.set("spark.ui.port", Integer.toString(webUIPort));
			conf.setJars(new String[] { KamResourceLoader.jPath_file });
			conf.set("spark.executor.memory", rm_exc_mem);
			conf.set("spark.ui.showConsoleProgress", "false");
			conf.set("spark.driver.maxResultSize", "4G");
		}
		conf.set("spark.scheduler.allocation.file", KamResourceLoader.loadFile("fairschedule.xml").getAbsolutePath());
		conf.set("spark.network.timeout", "800");
		if (other_config != null) {
			for (Tuple2<String, String> conf_tuple : other_config) {
				conf.set(conf_tuple._1, conf_tuple._2);
			}
		}
		return conf;
	}

	public JavaSparkContext getContext() {
		return context;
	}

	private static Random rand = new Random(0);

	public static void checkAndWait() throws Exception {

		internalInstance.context.parallelize(Arrays.asList(1)).map(ind -> {
			while (true) {
				Runtime runtime = Runtime.getRuntime();
				long allocatedMemory = (runtime.totalMemory() - runtime.freeMemory());
				// double presumableFreeMemory = (runtime.freeMemory()) / (1024.0 * 1024.0 *
				// 1024.0);
				// (runtime.maxMemory() - allocatedMemory) / (1024.0 * 1024.0 * 1024.0);
				double ratio = allocatedMemory * 1.0 / runtime.maxMemory();
				HashMap<Integer, Long> stats = internalInstance.getActiveJobRunTime();
				logger.info("Spark status: {} mem {} jobs", StringResources.FORMAT_AR3D.format(ratio),
						stats.toString());
				// logger.info("The available memory is {}G.", ratio);
				if (ratio < 0.7)
					break;
				if (stats.size() < 1)
					break;
				logger.info("Waiting for the resources to be released.", ratio);
				Thread.sleep(rand.nextInt(3000) + 1000);
			}
			return 0;
		}).collect();
	}

	public HashMap<Integer, Long> getActiveJobRunTime() {
		HashMap<Integer, Long> stats = new HashMap<>();
		for (int id : tracker.getActiveJobIds()) {
			SparkJobInfo info = tracker.getJobInfo(id);
			if (info != null) {
				int[] sids = tracker.getJobInfo(id).stageIds();
				List<SparkStageInfo> stages = Arrays.stream(sids).mapToObj(sid -> tracker.getStageInfo(sid))
						.collect(Collectors.toList());
				OptionalLong submission = stages.stream().mapToLong(sinf -> sinf.submissionTime())
						.filter(sinf -> sinf > 0).min();
				if (submission.isPresent()) {
					long min = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
					long sub = TimeUnit.MILLISECONDS.toSeconds(submission.getAsLong());
					long min_diff = min - sub;
					stats.put(id, min_diff);
				}
			}
		}
		// logger.info(" Jobs stats: {}", stats.toString());
		return stats;
	}

	public void init() {
		context = new JavaSparkContext(getConf());
		context.statusTracker();
		tracker = context.statusTracker();;

		scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(() -> {
			try {
				HashMap<Integer, Long> stats = getActiveJobRunTime();
				stats.entrySet().forEach(ent -> {
					if (ent.getValue() > timeout * 60) {
						logger.info("JOB {} timeout {}/{} minutes. Canceling..", ent.getKey(), ent.getValue(), timeout);
						context.sc().cancelJob(ent.getKey());
					}
				});

				// for (int id : tracker.getActiveJobIds()) {
				// SparkJobInfo info = tracker.getJobInfo(id).get();
				// if (info != null) {
				// int[] sids = tracker.getJobInfo(id).get().stageIds();
				// List<SparkStageInfo> stages = Arrays.stream(sids).mapToObj(sid ->
				// tracker.getStageInfo(sid))
				// .filter(opt -> opt.isDefined()).map(opt ->
				// opt.get()).collect(Collectors.toList());
				// logger.info("SPARK JOB CONTROLLER");
				// for (SparkStageInfo ssi : stages)
				// logger.info(" SPARK JID {} SID {} TIME {}", id, ssi.stageId(),
				// ssi.submissionTime());
				// OptionalLong submission = stages.stream().mapToLong(sinf ->
				// sinf.submissionTime())
				// .filter(sinf -> sinf > 0).min();
				// if (submission.isPresent()) {
				// long min = TimeUnit.MILLISECONDS.toMinutes(System.currentTimeMillis());
				// long sub = TimeUnit.MILLISECONDS.toMinutes(submission.getAsLong());
				// logger.info(" SPARK JID {} TIME {} CURRENT {}", id, sub, min);
				// long min_diff = min - sub;
				// if (min_diff > timeout) {
				// logger.info("JOB {} timeout {}/{} minutes. Canceling..", id, min_diff,
				// timeout);
				// context.sc().cancelJob(id);
				// }
				// }
				// }
				// }
			} catch (Exception e) {
				logger.error("Error when monitoring running spark jobs.", e);
			}
		}, 5, 5, TimeUnit.MINUTES);
	}

	public void close() {
		if (context != null)
			context.close();
		scheduler.shutdown();
	}

	public static void main(String[] args) {
		SparkInstance si = createLocalInstance();
		si.init();
		si.close();
	}

	public void poolPrioritize() {
		getContext().setLocalProperty("spark.scheduler.pool", "prioritize");
	}

}
