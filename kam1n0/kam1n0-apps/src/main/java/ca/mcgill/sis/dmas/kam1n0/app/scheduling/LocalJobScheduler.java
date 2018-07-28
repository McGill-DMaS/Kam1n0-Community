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
package ca.mcgill.sis.dmas.kam1n0.app.scheduling;

import static org.quartz.JobBuilder.newJob;
import static org.quartz.TriggerBuilder.newTrigger;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.quartz.JobDataMap;
import org.quartz.JobDetail;
import org.quartz.JobKey;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SchedulerFactory;
import org.quartz.Trigger;
import org.quartz.impl.matchers.GroupMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;

public class LocalJobScheduler {

	private static Logger logger = LoggerFactory.getLogger(LocalJobScheduler.class);

	private Scheduler jobScheduler;

	public Cache<Long, LocalJobProgress> jobStatusCacheCompleted;
	public ConcurrentHashMap<Long, LocalJobProgress> jobStatusCacheInProgress;

	public LocalJobScheduler(int cacheTimeInMinute, int cacheSize) throws Exception {
		SchedulerFactory schedFact = new org.quartz.impl.StdSchedulerFactory();
		jobScheduler = schedFact.getScheduler();
		jobScheduler.start();
		RemovalListener<Long, LocalJobProgress> removalListener = ent -> {
			logger.info("Removing expired result {}..", ent.getKey());
			if (ent.getValue() != null)
				if (ent.getValue().result != null)
					if (ent.getValue().result instanceof Closeable) {
						Closeable clResult = (Closeable) (ent.getValue().result);
						try {
							clResult.close();
						} catch (Exception e) {
							logger.error("Failed to clone resource .", e);
						}
					}
		};
		jobStatusCacheCompleted = CacheBuilder.newBuilder().concurrencyLevel(4).maximumSize(cacheSize)
				.expireAfterAccess(cacheTimeInMinute, TimeUnit.MINUTES).removalListener(removalListener).build();
		jobStatusCacheInProgress = new ConcurrentHashMap<>();
	}

	public synchronized void completeJob(LocalJobProgress jobProgress) {
		jobStatusCacheInProgress.remove(jobProgress.jobId);
		jobStatusCacheCompleted.put(jobProgress.jobId, jobProgress);
	}

	public LocalJobProgress getJobProgress(String userName, String taskName) {
		JobKey jkey = JobKey.jobKey(taskName, userName);
		long jid = constructJobId(jkey);
		if (jobStatusCacheInProgress.containsKey(jid))
			return jobStatusCacheInProgress.get(jid);
		else
			return jobStatusCacheCompleted.getIfPresent(jid);
	}

	public void addCompletedProgress(String user, String job, LocalJobProgress progress) {
		long id = constructJobId(JobKey.jobKey(job, user));
		progress.jobId = id;
		this.completeJob(progress);
	}

	public static long constructJobId(JobKey jKey) {
		return HashUtils.constructID(jKey.toString().getBytes());
	}

	public String submitJob(long appId, String appType, String appName, ApplicationResources res, String user,
			Class<? extends LocalDmasJobProcedure> procedure, Map<String, Object> parameters) throws Exception {
		JobDataMap params = new JobDataMap();
		String jobName = LocalDmasJobProcedure.getJobName(procedure);
		if (checkPolicy(user, jobName)) {
			try {
				LocalJobProgress progress = new LocalJobProgress(constructJobId(JobKey.jobKey(jobName, user)), appId,
						appName, this::completeJob);

				LocalDmasJobProcedure.initDataMap(appId, appType, res, user, jobName, progress, parameters, params);

				JobDetail job = newJob(procedure).withIdentity(jobName, user).usingJobData(params).build();
				this.jobStatusCacheInProgress.put(progress.jobId, progress);

				Trigger trigger = newTrigger().forJob(job).startNow().build();

				jobScheduler.scheduleJob(job, trigger);

				return Long.toString(progress.jobId);
			} catch (SchedulerException e) {
				logger.error("Failed to schedule the job [" + jobName + "] for user [" + user + "]", e);
				throw new Exception("Failed to schedule the job.");
			}
		} else {
			throw new Exception("You already have a running job of the task [" + jobName + "].");
		}
	}

	public boolean checkPolicy(String user, String taskName) {
		try {
			JobKey key = JobKey.jobKey(taskName, user);
			boolean terminated = !jobScheduler.checkExists(key);
			if (terminated)
				jobStatusCacheInProgress.remove(constructJobId(key));
			return terminated; // && !jobStatusCacheInProgress.containsKey(constructJobId(key));
		} catch (SchedulerException e) {
			return false;
		}
	}

	public ArrayList<LocalDmasJobInfo> listJobs() {
		try {
			ArrayList<LocalDmasJobInfo> infos = new ArrayList<>();

			for (String groupName : jobScheduler.getJobGroupNames()) {
				for (JobKey key : jobScheduler.getJobKeys(GroupMatcher.jobGroupEquals(groupName))) {

					Trigger trigger = jobScheduler.getTriggersOfJob(key).get(0);
					JobDetail details = jobScheduler.getJobDetail(key);
					JobDataMap map = details.getJobDataMap();

					String user = LocalDmasJobProcedure.getUser(map);
					LocalJobProgress progress = LocalDmasJobProcedure.getProgress(map);

					LocalDmasJobInfo info = new LocalDmasJobInfo();
					info.userKey = user;
					info.taskName = key.getName();
					info.lastStage = progress.stages.get(progress.stages.size() - 1);
					info.runtime = (new Date()).getTime() - trigger.getFinalFireTime().getTime();
					info.startingTime = trigger.getFinalFireTime().getTime();
					info.progress = progress;
					// info.userRoles = user.roles.toString();

					infos.add(info);
				}
			}
			return infos;

		} catch (SchedulerException e) {
			logger.error("Failed to load all the job infos.", e);
			return null;
		}
	}

	public ArrayList<LocalDmasJobInfo> listJobs(String userKey, String userRoles) {
		try {
			ArrayList<LocalDmasJobInfo> infos = new ArrayList<>();
			Set<JobKey> cJobs = jobScheduler.getJobKeys(GroupMatcher.jobGroupEquals(userKey));

			for (JobKey key : cJobs) {

				Trigger trigger = jobScheduler.getTriggersOfJob(key).get(0);
				JobDetail details = jobScheduler.getJobDetail(key);
				JobDataMap map = details.getJobDataMap();

				LocalJobProgress progress = LocalDmasJobProcedure.getProgress(map);

				LocalDmasJobInfo info = new LocalDmasJobInfo();
				info.userKey = userKey;
				info.taskName = key.getName();
				info.lastStage = progress.stages.get(progress.stages.size() - 1);
				info.runtime = (new Date()).getTime() - trigger.getFinalFireTime().getTime();
				info.startingTime = trigger.getFinalFireTime().getTime();
				info.userRoles = userRoles;
				info.progress = progress;
				infos.add(info);
			}
			return infos;

		} catch (SchedulerException e) {
			logger.error("Failed to load all the job infos.", e);
			return null;
		}
	}

	public List<LocalDmasJobInfo> listJobs(String uname) {
		return listJobs(uname, StringResources.STR_EMPTY);
	}

	public void close() {
		try {
			jobScheduler.shutdown(false);
		} catch (SchedulerException e) {
			logger.error("Failed to shutsown job scheduler.", e);
		}
	}

}
