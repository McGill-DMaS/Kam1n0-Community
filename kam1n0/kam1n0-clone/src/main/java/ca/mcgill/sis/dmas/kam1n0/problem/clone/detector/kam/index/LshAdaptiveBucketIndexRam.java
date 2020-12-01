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
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.function.Function;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class LshAdaptiveBucketIndexRam extends LshAdaptiveBucketIndexAbstract {

	public LshAdaptiveBucketIndexRam(SparkInstance sparkInstance, int initialDepth, int maxDepth, int maxSize,
			Function<Integer, Integer> nextDepth) {
		super(sparkInstance, initialDepth, maxDepth, maxSize, nextDepth);

	}

	public Table<Long, String, TreeMap<String, HashSet<Long>>> data = HashBasedTable.create();

	@Override
	public boolean clearHid(long rid, String primaryKey, String secondaryKey) {
		TreeMap<String, HashSet<Long>> clMap = data.get(rid, primaryKey);
		if (clMap == null)
			return false;
		clMap.put(secondaryKey, new HashSet<>());
		return true;
	}

	@Override
	public HashSet<Long> getHids(long rid, String primaryKey, String secondaryKey) {
		TreeMap<String, HashSet<Long>> clMap = data.get(rid, primaryKey);
		if (clMap == null)
			return null;
		HashSet<Long> hids = clMap.get(secondaryKey);
		return hids;
	}

	@Override
	public boolean putHid(long rid, String primaryKey, String secondaryKey, int newDepth, Long hid) {
		TreeMap<String, HashSet<Long>> clMap = data.get(rid, primaryKey);
		if (clMap == null) {
			clMap = new TreeMap<>();
			data.put(rid, primaryKey, clMap);
		}
		clMap.compute(secondaryKey, (k, v) -> {
			if (v == null)
				v = new HashSet<>();
			v.add(hid);
			return v;
		});
		return true;
	}

	@Override
	public boolean putHid(long rid, String primaryKey, String secondaryKey, HashSet<Long> hids) {
		TreeMap<String, HashSet<Long>> clMap = data.get(rid, primaryKey);
		if (clMap == null) {
			clMap = new TreeMap<>();
			data.put(rid, primaryKey, clMap);
		}
		HashSet<Long> oldHids = clMap.get(secondaryKey);
		if (oldHids == null)
			clMap.put(secondaryKey, hids);
		else
			oldHids.addAll(hids);
		return true;
	}

	@Override
	public AdaptiveBucket nextOnTheLeft(long rid, AdaptiveBucket target) {
		if (target.cKey == rootClusteringKey)
			return null;
		TreeMap<String, HashSet<Long>> clMap = data.get(rid, target.pkey);
		if (clMap == null) {
			return null;
		}
		Entry<String, HashSet<Long>> entry = clMap.lowerEntry(target.cKey);
		if (entry == null)
			return null;
		else
			return new AdaptiveBucket(target.pkey, entry.getKey(), target.depth, entry.getValue());
	}

	@Override
	public AdaptiveBucket nextOnTheRight(long rid, AdaptiveBucket target) {
		if (target.cKey == rootClusteringKey)
			return null;
		TreeMap<String, HashSet<Long>> clMap = data.get(rid, target.pkey);
		if (clMap == null) {
			return null;
		}
		Entry<String, HashSet<Long>> entry = clMap.higherEntry(target.cKey);
		if (entry == null)
			return null;
		else
			return new AdaptiveBucket(target.pkey, entry.getKey(), target.depth, entry.getValue());
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
	public boolean clearAll(long rid) {
		data.rowKeySet().remove(rid);
		return true;
	}

}
