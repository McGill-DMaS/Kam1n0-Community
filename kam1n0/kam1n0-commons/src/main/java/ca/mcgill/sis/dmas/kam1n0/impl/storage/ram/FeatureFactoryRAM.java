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

import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.FeatureVecFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.FeatureVec;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class FeatureFactoryRAM extends FeatureVecFactory {

	transient SparkInstance sparkInstance;

	public FeatureFactoryRAM(SparkInstance sparkInstance) {
		this.sparkInstance = sparkInstance;
	}

	public HashMap<Long, FeatureVec> map = new HashMap<>();

	@Override
	public boolean putVec(List<FeatureVec> vec) {
		vec.forEach(ve -> map.put(ve.key, ve));
		return true;
	}

	@Override
	public List<FeatureVec> getVecs(List<Long> keys) {
		return keys //
				.stream() //
				.map(key -> map.get(key)) //
				.filter(val -> val != null)//
				.collect(Collectors.toList());
	}

	@Override
	public boolean dropVec(List<Long> keys) {
		keys.forEach(map::remove);
		return true;
	}

	@Override
	public void init() {
		map = new HashMap<>();
	}

	@Override
	public void close() {
		map = null;
	}

	@Override
	public List<FeatureVec> getVecs(Set<Long> keys) {
		return keys.stream().map(key -> map.get(key))
				.filter(vec -> vec != null).collect(Collectors.toList());
	}

	@Override
	public JavaRDD<FeatureVec> getVecsAsRDD(Set<Long> keys) {
		return this.sparkInstance.getContext().parallelize(getVecs(keys));
	}

	private static Logger logger = LoggerFactory
			.getLogger(FeatureFactoryRAM.class);

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
