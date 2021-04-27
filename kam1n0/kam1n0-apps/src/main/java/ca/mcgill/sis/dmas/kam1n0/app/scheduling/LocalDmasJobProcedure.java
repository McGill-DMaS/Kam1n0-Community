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

import java.io.File;
import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import org.quartz.InterruptableJob;
import org.quartz.JobDataMap;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.UnableToInterruptJobException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;

public abstract class LocalDmasJobProcedure implements InterruptableJob {
	private final static Logger logger = LoggerFactory.getLogger(LocalDmasJobProcedure.class);
	private final static String KEY_USER_STRING = "KEY_USER_STRING";
	private final static String KEY_APP_ID = "KEY_APP_ID";
	private final static String KEY_APP_RES = "KEY_APP_RES";
	private final static String KEY_APP_TYPE = "KEY_APP_TYPE";
	private final static String KEY_PROGRESS_LOCALPROGRESS = "KEY_PROGRESS_LOCALPROGRESS";
	private final static String KEY_TASKNAME = "KEY_TASKNAME";
	private final static String KEY_PARAMS = "KEY_PARAMS";

	public static String getUser(JobDataMap context) {
		return (String) context.get(KEY_USER_STRING);
	}

	public static LocalJobProgress getProgress(JobDataMap context) {
		return (LocalJobProgress) context.get(KEY_PROGRESS_LOCALPROGRESS);
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> getParameterMap(JobDataMap context) {
		return (Map<String, Object>) context.get(KEY_PARAMS);
	}

	public static Long getAppId(JobDataMap context) {
		return (Long) context.get(KEY_APP_ID);
	}

	public static ApplicationResources getAppResource(JobDataMap context) {
		return (ApplicationResources) context.get(KEY_APP_RES);
	}

	public static void initDataMap(long appId, String appType, ApplicationResources appRes, String user, String jobName,
			LocalJobProgress progress, Map<String, Object> parameters, JobDataMap params) {
		params.put(KEY_USER_STRING, user);
		params.put(KEY_PROGRESS_LOCALPROGRESS, progress);
		params.put(KEY_TASKNAME, jobName);
		params.put(KEY_PARAMS, parameters);
		params.put(KEY_APP_ID, appId);
		params.put(KEY_APP_RES, appRes);
		params.put(KEY_APP_TYPE, appType);
	}

	public static String getJobName(Class<? extends LocalDmasJobProcedure> procedure) {
		JobNameAnnotation annotation = procedure.getAnnotation(JobNameAnnotation.class);
		return annotation.jobName();
	}

	public String getJobName() {
		return getJobName(this.getClass());
	}

	public abstract void runProcedure(long appId, String appType, ApplicationResources appRes, String userName,
			LocalJobProgress progress, Map<String, Object> dataMap);

	@Override
	public void execute(JobExecutionContext context) throws JobExecutionException {

		JobDataMap dataMap = context.getJobDetail().getJobDataMap();
		LocalJobProgress progress = getProgress(dataMap);
		Map<String, Object> parameters = getParameterMap(dataMap);

		String user = getUser(dataMap);
		String appType = getAppType(dataMap);
		ApplicationResources res = getAppResource(dataMap);
		Long appId = getAppId(dataMap);
		if (res == null || appId == null || user == null) {
			String errorMessage = getAccessViolationMessage(res, appId, user);
			logger.error(errorMessage);
			StageInfo stage = progress.nextStage(LocalDmasJobProcedure.class, "Invalid request! " + errorMessage);
			stage.complete();
			progress.complete(errorMessage);
		} else
			this.runProcedure(appId, appType, res, user, progress, parameters);
	}

	private String getAccessViolationMessage(ApplicationResources res, Long appId, String user) {
		String subMessage = "Error.";
		if (res == null) {
			subMessage = "Application resource not found.";
		}
		if (appId == null) {
			subMessage = subMessage + " Application Id not found.";
		}
		if (user == null) {
			subMessage = subMessage + " User not found.";
		}
		String message = "Access violation. " + subMessage;
		return message;
	}

	private String getAppType(JobDataMap dataMap) {
		return (String) dataMap.get(KEY_APP_TYPE);
	}

	public int getInteger(String name, Map<String, Object> map, int deflt) throws Exception {
		try {
			return map.containsKey(name) ? (Integer) map.get(name) : deflt;
		} catch (Exception e) {
			throw new Exception("The required param " + name + " is not filled with correct format. ");
		}
	}
	
	public String getString(String name, Map<String, Object> map, String deflt) throws Exception {
		try {
			return map.containsKey(name) ? (String) map.get(name) : deflt;
		} catch (Exception e) {
			throw new Exception("The required param " + name + " is not filled with correct format. ");
		}
	}

	public long getLong(String name, Map<String, Object> map, long deflt) throws Exception {
		try {
			return map.containsKey(name) ? (Long) map.get(name) : deflt;
		} catch (Exception e) {
			throw new Exception("The required param " + name + " is not filled with correct format. ");
		}
	}

	public double getDouble(String name, Map<String, Object> map, double deflt) throws Exception {
		try {
			return map.containsKey(name) ? (double) map.get(name) : deflt;
		} catch (Exception e) {
			throw new Exception("The required param " + name + " is not filled with correct format. ");
		}
	}

	public boolean getBoolean(String name, Map<String, Object> map, boolean deflt) throws Exception {
		try {
			return map.containsKey(name) ? (boolean) map.get(name) : deflt;
		} catch (Exception e) {
			throw new Exception("The required param " + name + " is not filled with correct format. ");
		}
	}

	@SuppressWarnings("unchecked")
	public List<File> getFiles(String name, Map<String, Object> map) throws Exception {
		try {
			return (List<File>) map.get(name);
		} catch (Exception e) {
			throw new Exception("The required param files is not filled with correct format. ");
		}
	}

	@SuppressWarnings("unchecked")
	public <T> T getObj(String name, Map<String, Object> map) throws Exception {
		try {
			return (T) map.get(name);
		} catch (Exception e) {
			throw new Exception("The required param files is not filled with correct format. ");
		}
	}

	@Override
	public void interrupt() throws UnableToInterruptJobException {
	}

}
