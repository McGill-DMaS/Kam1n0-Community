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
package ca.mcgill.sis.dmas.nlp.model.astyle;


import java.text.DecimalFormat;
import java.util.Date;
import java.util.function.Predicate;
import java.util.stream.IntStream;

import org.slf4j.Logger;

public class GradientProgress {
	private static DecimalFormat doubleFormat = new DecimalFormat("00.000000");
	private static DecimalFormat doubleFormat22 = new DecimalFormat("00.00");
	private static DecimalFormat intFormat2 = new DecimalFormat("00");
	private static DecimalFormat intFormat3 = new DecimalFormat("000");

	public GradientProgress(long totalCount) {
		this.totalCount = totalCount;
	}

	public long totalCount = 0;
	public long startTime = 0;

	public void start(Logger logger) {
		startTime = System.currentTimeMillis();
		logger.info("Starting...");
	}

	public void complete(Logger logger) {
		long now = System.currentTimeMillis();
		long takenTime = (now - startTime);
		long takenTimes = takenTime / 1000;
		int css = (int) (takenTimes % 60);
		int cmin = (int) (takenTimes / 60);
		int chh = cmin / 60;
		cmin %= 60;
		double speed = totalCount * 1.0 / takenTime;
		logger.info("Competed in {}:{}:{}.{} avg speed: {}k/s", intFormat2.format(chh), intFormat2.format(cmin),
				intFormat2.format(css), intFormat3.format(takenTime % 1000), doubleFormat.format(speed));
	}

	public void reportIfProgressSatisfied(Logger logger, long count, double alpha, Predicate<Double> condition) {
		double progress = 100.0 * (count) / totalCount;
		if (condition.test(progress))
			report(logger, count, alpha);
	}

	public void report(Logger logger, long count, double alpha) {
		long now = System.currentTimeMillis();
		long diff = now - startTime;
		double progress = 100.0 * (count) / totalCount;
		double speed = count * 1.0 / diff;

		long remainingTime = (long) ((totalCount - count) / speed / 1000);
		long takenTime = (now - startTime) / 1000;

		int fss = (int) (remainingTime % 60);
		int fmin = (int) (remainingTime / 60);
		int fhh = fmin / 60;
		fmin %= 60;

		int css = (int) (takenTime % 60);
		int cmin = (int) (takenTime / 60);
		int chh = cmin / 60;
		cmin %= 60;

		Runtime runtime = Runtime.getRuntime();
		double maxMemory = runtime.maxMemory() * 1.0 / 1024 / 1024 / 1024;
		double allocatedMemory = runtime.totalMemory() * 1.0 / 1024 / 1024 / 1024;
		double freeMemory = runtime.freeMemory() * 1.0 / 1024 / 1024 / 1024;

		logger.info("alp:{} prog:{}% word/s:{}k left:{}:{}:{} elapsed:{}:{}:{} mem: {}-{}-{}",
				doubleFormat.format(alpha), doubleFormat.format(progress), intFormat3.format(speed),
				intFormat2.format(fhh), intFormat2.format(fmin), intFormat2.format(fss), intFormat2.format(chh),
				intFormat2.format(cmin), intFormat2.format(css), doubleFormat22.format(maxMemory),
				doubleFormat22.format(allocatedMemory), doubleFormat22.format(freeMemory));

	}
}
