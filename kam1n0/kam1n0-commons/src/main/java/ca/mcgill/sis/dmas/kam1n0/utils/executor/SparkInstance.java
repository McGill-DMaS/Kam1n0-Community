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
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.spark.SparkConf;
import org.apache.spark.SparkJobInfo;
import org.apache.spark.SparkStatusTracker;
import org.apache.spark.api.java.JavaSparkContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
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

	public int core_localMode = 4;
	public boolean localMode = true;
	public int timeout = 10;

	private JavaSparkContext context;
	private SparkStatusTracker tracker;
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

	public static SparkInstance createLocalInstance(List<Tuple2<String, String>> otherConfigs) {
		String core = System.getProperty("spark.local.cores", "4");
		String min = System.getProperty("spark.job.timeout.min", "10");
		String web = System.getProperty("spark.web", "true");
		SparkInstance spark = new SparkInstance(Integer.parseInt(core), Boolean.parseBoolean(web), 4040, otherConfigs);
		spark.timeout = Integer.parseInt(min);
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
			conf.setMaster("local[" + core_localMode + "]");
			conf.set("spark.ui.enabled", Boolean.toString(showWebUI));
			conf.set("spark.ui.port", Integer.toString(webUIPort));
			conf.setAppName("Kam1n0-Spark");
			conf.set("spark.scheduler.mode", "FAIR");
			conf.set("spark.ui.showConsoleProgress", "false");
		} else {
			conf.setMaster("spark://" + host + ":" + driverport);
			conf.setAppName("Kam1n0-Spark");
			conf.set("spark.ui.enabled", Boolean.toString(showWebUI));
			conf.set("spark.ui.port", Integer.toString(webUIPort));
			conf.setJars(new String[] { KamResourceLoader.jPath_file });
			conf.set("spark.executor.memory", rm_exc_mem);
			conf.set("spark.ui.showConsoleProgress", "false");
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

	public void init() {
		context = new JavaSparkContext(getConf());
		tracker = new SparkStatusTracker(context.sc());

		scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(() -> {
			try {
				for (int id : tracker.getActiveJobIds()) {
					SparkJobInfo info = tracker.getJobInfo(id).get();
					if (info != null) {
						int[] sids = tracker.getJobInfo(id).get().stageIds();
						OptionalLong submission = Arrays.stream(sids).mapToObj(sid -> tracker.getStageInfo(sid).get())
								.filter(sinf -> sinf != null).mapToLong(sinf -> sinf.submissionTime()).min();
						if (submission.isPresent()) {
							long min = TimeUnit.MILLISECONDS.toMinutes(System.currentTimeMillis());
							long min_diff = min - submission.getAsLong();
							if (min_diff > timeout) {
								logger.info("JOB {} timeout {}/{} minutes. Canceling..", id, min_diff, timeout);
								context.sc().cancelJob(id);
							}
						}
					}
				}
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
