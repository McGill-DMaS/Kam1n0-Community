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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index;

import java.util.HashSet;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragmentNormalized;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

/***
 * 
 * T represents the information to be stored for each objects that share same
 * hash (identical content but different meta-data). Class T needs to be
 * registered in VecInfo
 *
 * user/repository isolation, L isolation, is done through building different
 * prefix into the primary key (unique hash of VecInfo).
 * 
 * @param <T>
 */
public abstract class LshAdaptiveDupFuncIndex<T extends VecInfo, K extends VecInfoShared> {

	protected SparkInstance sparkInstance;
	protected BiFunction<AsmFragmentNormalized, Integer, byte[]> hasher;

	private static Logger logger = LoggerFactory.getLogger(LshAdaptiveDupFuncIndex.class);

	public LshAdaptiveDupFuncIndex(SparkInstance sparkInstance) {
		this.sparkInstance = sparkInstance;
	}

	public abstract void dump(String file);

	protected void calFullKey(VecEntry<T, K> vec) {
		if (vec.fullKey == null)
			if (vec.calculator != null)
				vec.fullKey = vec.calculator.calculate(); // this.hasher.apply(vec.tkns, vec.ind);
			else
				logger.error("vector's fullkey is none but it does not ship with a calculator..");

	}

	/**
	 * Update existed hids and get non-existed hids
	 * 
	 * @param vecs
	 * @return
	 */
	public abstract List<VecEntry<T, K>> update(long rid, List<VecEntry<T, K>> vecs, StageInfo info);

	// public abstract JavaPairRDD<Long, Tuple2<T, D>> getVidsAsRDD(HashSet<Long>
	// hids, int topK);

	public abstract JavaRDD<VecEntry<T, K>> getVecEntryInfoAsRDD(long rid, HashSet<Long> hashIds,
			boolean excludeIndividualInfo, Function<List<T>, List<T>> filter);

	public abstract void init();

	public abstract void close();

	public abstract void clear(long rid);

}
