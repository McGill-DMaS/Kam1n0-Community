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

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.spark.api.java.JavaRDD;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class LshAdaptiveDupIndexRam<T extends VecInfo, K extends VecInfoShared> extends LshAdaptiveDupFuncIndex<T, K> {

	public LshAdaptiveDupIndexRam(SparkInstance sparkInstance) {
		super(sparkInstance);
	}

	public Table<Long, Long, VecEntry<T, K>> data = HashBasedTable.create();

	@Override
	public List<VecEntry<T, K>> update(long rid, List<VecEntry<T, K>> vecs, StageInfo info) {
		return vecs.stream().map(vec -> {
			VecEntry<T, K> tvec = data.get(rid, vec.hashId);
			if (tvec == null) {
				this.calFullKey(vec);
				data.put(rid, vec.hashId, vec);
				return vec;
			} else {
				tvec.vids.addAll(vec.vids);
				return null;
			}
		}).filter(vec -> vec != null).collect(Collectors.toList());
	}

	// @Override
	// public JavaPairRDD<Long, Tuple2<T, D>> getVidsAsRDD(HashSet<Long> hids, int
	// topK) {
	// List<Tuple2<Long, Tuple2<T, D>>> res = hids.stream().map(hid -> new
	// Tuple2<>(hid, data.get(hid)))
	// .filter(tp -> tp._2().vids.size() < 100).filter(tp -> tp._2 != null)
	// .flatMap(tp -> tp._2.vids.stream().map(vid -> new Tuple2<>(tp._1, new
	// Tuple2<>(vid, tp._2.sharedInfo))))
	// .collect(Collectors.toList());
	// return this.sparkInstance.getContext().parallelizePairs(res);
	// }

	@Override
	public JavaRDD<VecEntry<T, K>> getVecEntryInfoAsRDD(long rid, HashSet<Long> hashIds, boolean excludeBlockIds,
			Function<List<T>, List<T>> filter) {
		return this.sparkInstance.getContext().parallelize(
				hashIds.stream().map(id -> data.get(rid, id)).filter(ent -> ent != null).collect(Collectors.toList()));
	}

	@Override
	public void init() {
		data = HashBasedTable.create();
	}

	@Override
	public void close() {
		data = null;
	}

	@Override
	public void dump(String file) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			mapper.writerWithDefaultPrettyPrinter().writeValue(new File(DmasApplication.applyDataContext(file)), this);
		} catch (Exception e) {
			System.out.print("Failed to serialize this object /n" + e.getMessage());
			e.printStackTrace();
		}
	}

	@Override
	public void clear(long rid) {
		data.rowKeySet().remove(rid);

	}

}
