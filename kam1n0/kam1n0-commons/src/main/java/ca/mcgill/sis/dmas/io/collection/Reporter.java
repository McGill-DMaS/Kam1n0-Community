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

import org.slf4j.Logger;

import ca.mcgill.sis.dmas.env.StringResources;

public class Reporter {

	public long count = 0;
	public long total = 0;
	private int gate = 1;
	private int gateInc = 1;
	private Logger logger;

	public Reporter(long start, long total, int gatInc, Logger logger) {
		this.count = start;
		this.total = total;
		this.logger = logger;
		this.gateInc = gatInc;
	}

	public Reporter(long total, Logger logger) {
		this(0, total, 1, logger);
	}

	public Reporter(long total, int gateInc, Logger logger) {
		this(0, total, gateInc, logger);
	}

	public void inc() {
		inc(1);
	}

	public void inc(long val) {
		this.count += val;
		if (count * 100.0 / total >= gate) {
			gate+=gateInc;
			logger.info("Progress {}/{} {}%", count, total, StringResources.FORMAT_2R2D.format(count * 100.0 / total));
		}
	}

	public double prog() {
		return this.count * 100.0 / this.total;
	}

}
