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
package ca.mcgill.sis.dmas.kam1n0.impl.storage.ram;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.Bucket;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketIndex;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class BucketIndexRAM extends BucketIndex {

	public HashMap<String, Bucket> cache = new HashMap<>();

	public transient SparkInstance ins;

	public BucketIndexRAM(SparkInstance ins) {
		this.ins = ins;
	}

	@Override
	public void init() {
		cache = new HashMap<>();
	}

	@Override
	public boolean close() {
		cache = null;
		return true;
	}

	@Override
	public boolean put(String bucketID, long value) {
		cache.compute(bucketID, (k, v) -> {
			if (v == null) {
				Bucket bucket = new Bucket();
				bucket.key = k;
				bucket.value.add(value);
				return bucket;
			} else {
				v.value.add(value);
				return v;
			}
		});
		return true;
	}

	@Override
	public boolean drop(String bucketID, long value) {
		Bucket bucket = cache.get(bucketID);
		if (bucket != null)
			bucket.value.remove(value);
		return true;
	}

	@Override
	public boolean put(String bucketID, HashSet<Long> values) {
		Bucket bucket = new Bucket(bucketID, values);
		cache.compute(bucketID, (k, v) -> {
			if (v == null)
				return bucket;
			v.value.addAll(bucket.value);
			return v;
		});
		return true;
	}

	@Override
	public boolean put(ArrayList<Bucket> bucketMap) {
		bucketMap.forEach(bucket -> cache.compute(bucket.key, (k, v) -> {
			if (v == null)
				return bucket;
			v.value.addAll(bucket.value);
			return v;
		}));
		return true;
	}

	@Override
	public List<Bucket> fetch(List<String> bucketIDs) {
		return bucketIDs.stream().map(id -> cache.get(id))
				.filter(val -> val != null).collect(Collectors.toList());
	}

	@Override
	public JavaRDD<Bucket> fetchAsRDD(List<String> bucketIDs) {
		return ins.getContext().parallelize(fetch(bucketIDs));
	}

	@Override
	public Bucket fetch(String bucketID) {
		return cache.get(bucketID);
	}

	@Override
	public boolean drop(String bucketID) {
		return cache.remove(bucketID) != null;
	}

	private static Logger logger = LoggerFactory
			.getLogger(BucketIndexRAM.class);

	@Override
	public String toString() {
		ObjectMapper mapper = new ObjectMapper();
		try {
			return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(
					this);
		} catch (JsonProcessingException e) {
			logger.error("Failed to serialize this object",e);
			return StringResources.STR_EMPTY;
		}
	}
}
