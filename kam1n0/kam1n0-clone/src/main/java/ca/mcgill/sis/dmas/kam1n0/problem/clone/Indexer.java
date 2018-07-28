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
package ca.mcgill.sis.dmas.kam1n0.problem.clone;

import java.util.List;
import java.util.Set;
import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import scala.Tuple2;
import scala.Tuple3;

/**
 * Added multi-tenancy support
 *
 * @param <T>
 */
public abstract class Indexer<T> {

	private static Logger logger = LoggerFactory.getLogger(Indexer.class);

	protected SparkInstance sparkInstance;

	public Indexer(SparkInstance sparkInstance) {
		this.sparkInstance = sparkInstance;
	}

	public Indexer() {
	}

	public abstract String params();

	public abstract boolean index(long rid, List<T> targets, LocalJobProgress progress);

	public abstract List<Tuple2<T, Double>> query(long rid, T target, double threshold, int topK);

	public abstract void init();

	public abstract void close();

	public abstract JavaRDD<Tuple3<T, T, Double>> queryAsRdds(long rid, List<T> targets, Set<Tuple2<Long, Long>> links,
			int topK);

	public boolean dump(String path) {
		logger.warn(
				"Receiving command to dump the index of this detector; but the underlying detector implementation does not implement such functionality.");
		return false;
	}

	public void clear(long rid) {
	}

}
