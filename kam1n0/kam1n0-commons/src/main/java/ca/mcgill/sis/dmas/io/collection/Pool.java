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
package ca.mcgill.sis.dmas.io.collection;

import java.util.concurrent.Callable;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pool {

	public int numberOfThreads = 4;

	public static void FOR(final Task task) {
		Pool pool = new Pool(4);
		pool.submitSingleTask(task);
		pool.waiteForCompletion();
	}

	public static void FOR(final Task task, int numberOfThreads) {
		Pool pool = new Pool(numberOfThreads);
		pool.submitSingleTask(task);
		pool.waiteForCompletion();
	}

	public static int numberOfLogicalCores() {
		return Runtime.getRuntime().availableProcessors();
	}

	private static Logger logger = LoggerFactory.getLogger(Pool.class);

	ThreadPoolExecutor threadPoolExecutor;

	public Pool(int numberOfThread) {
		this.numberOfThreads = numberOfThread;
		threadPoolExecutor = new ThreadPoolExecutor(numberOfThread,
				numberOfThread, 0L, TimeUnit.MILLISECONDS,
				new LinkedBlockingQueue<Runnable>());
	}

	public void submitSingleTask(final Task task) {
		threadPoolExecutor.submit(new Callable<Void>() {
			@Override
			public Void call() throws Exception {
				try {
					task.run();
				} catch (Exception e) {
					logger.error("Error in execution.", e);
				}
				return null;
			}
		});
	}

	public void start(final Task task) {
		for (int i = 0; i < numberOfThreads; ++i) {
			threadPoolExecutor.submit(new Callable<Void>() {
				@Override
				public Void call() throws Exception {
					try {
						task.run();
					} catch (Exception e) {
						logger.error("Error in execution.", e);
					}
					return null;
				}
			});
		}
	}

	public Pool start(final TaskWithInd task) {
		for (int i = 0; i < numberOfThreads; ++i) {
			final int ind = i;
			threadPoolExecutor.submit(new Callable<Void>() {
				@Override
				public Void call() throws Exception {
					try {
						task.run(ind);
					} catch (Exception e) {
						logger.error("Error in execution.", e);
					}
					return null;
				}
			});
		}
		return this;
	}

	public boolean waiteForCompletion() {
		// wait for threads to complete
		threadPoolExecutor.shutdown();
		try {
			threadPoolExecutor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			logger.error("Being interrupted while doing training..", e);
			return false;
		}
		return true;
	}

	public static interface Task {
		public void run() throws Exception;
	}

	public static interface TaskWithInd {
		public void run(int id) throws Exception;
	}

}
