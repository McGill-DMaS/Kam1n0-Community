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
package ca.mcgill.sis.dmas.env;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.utils.src.FormatMilliseconds;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class LocalJobProgress {

	public volatile static boolean enablePrint = false;
	public volatile static boolean enableLogging = false;
	private static Logger logger = LoggerFactory.getLogger(LocalJobProgress.class);

	public class JobProgressWrapper {
		public List<StageInfo> stages;
		public int timeOut = 0;
		public boolean completed = false;
		public Object result = null;
		public String appName;
		public long appId;
	}

	public JobProgressWrapper toWrapper(int[] index, int timeout) {
		JobProgressWrapper wrapper = new JobProgressWrapper();
		wrapper.stages = Arrays.stream(index).filter(ind -> ind >= 0 && ind < stages.size()).mapToObj(stages::get)
				.collect(Collectors.toList());
		int maxRequestedInd = Arrays.stream(index).max().getAsInt();
		if (maxRequestedInd < stages.size() - 1) {
			for (int ind = maxRequestedInd + 1; ind < stages.size(); ++ind)
				wrapper.stages.add(stages.get(ind));
		}
		wrapper.timeOut = timeout;
		wrapper.completed = completed;
		wrapper.result = result;
		wrapper.appId = appId;
		wrapper.appName = appName;
		return wrapper;
	}

	public Object result = null;
	public boolean interrupted = false;
	public boolean completed = false;
	public String appName;
	public long appId;

	@JsonIgnore
	public long jobId = -1;

	@JsonIgnore
	public ArrayList<StageInfo> stages = new ArrayList<>();
	@JsonIgnore
	public Stack<StageInfo> stack = new Stack<>();
	@JsonIgnore
	public Consumer<LocalJobProgress> completedHook = null;

	public static class StageInfo {
		@JsonIgnore
		public String callerClass;
		@JsonIgnore
		public String header;
		@JsonIgnore
		public String originalMsg;

		public String msg;
		public long startTime = System.currentTimeMillis();
		public double progress;
		public int ind = -1;
		public boolean completed = false;

		public <T> StageInfo(Class<T> callerClass, String header, int ind, String msg, Object... params) {
			this.callerClass = callerClass.getSimpleName();
			msg = StringResources.parse(msg, params);
			this.msg = "[ " + header + (header.trim().length() < 1 ? "" : ".") + this.callerClass + " ]: " + msg
					+ "...";
			if (enableLogging)
				logger.info(this.msg);
			if (enablePrint)
				System.out.println(this.msg);
			this.ind = ind;
			this.header = header;
			this.originalMsg = msg;
		}

		public void updateMsg(String msg, Object... params) {
			msg = StringResources.parse(msg, params);
			this.msg = "[ " + header + (header.trim().length() < 1 ? "" : ".") + this.callerClass + " ]: " + msg
					+ "...";
			if (enableLogging)
				logger.info(this.msg);
			if (enablePrint)
				System.out.println(this.msg);
		}

		public void complete() {
			progress = 1.0;
			completed = true;
			this.msg = this.msg + " [ completed in " + FormatMilliseconds.ToReadableTime(System.currentTimeMillis() - startTime) + " ]";
			if (enableLogging)
				logger.info(this.msg);
			if (enablePrint)
				System.out.println(this.msg);
		}
	}

	public LocalJobProgress(long id, long appId, String appName, Consumer<LocalJobProgress> completedHook) {
		this.jobId = id;
		this.completedHook = completedHook;
		this.appId = appId;
		this.appName = appName;
	}

	public LocalJobProgress() {
		this.jobId = -1;
		this.completedHook = null;
	}

	public String constructHeader() {
		if (stack.isEmpty())
			return StringResources.STR_EMPTY;
		else
			return stack.peek().callerClass;
	}

	public synchronized <T> StageInfo nextStage(Class<T> callerClass, String msg, Object... params) {
		StageInfo stage = new StageInfo(callerClass, constructHeader(), stages.size(), msg, params);
		stack.push(stage);
		stages.add(stage);
		return stage;
	}

	public synchronized <T> StageInfo nextStage(Class<T> callerClass) {
		StageInfo stage = new StageInfo(callerClass, constructHeader(), stages.size(), StringResources.STR_EMPTY);
		stack.push(stage);
		stages.add(stage);
		return stage;
	}
	
	public void complete() {
		this.completed = true;
		if (this.completedHook != null)
			this.completedHook.accept(this);
	}
}
