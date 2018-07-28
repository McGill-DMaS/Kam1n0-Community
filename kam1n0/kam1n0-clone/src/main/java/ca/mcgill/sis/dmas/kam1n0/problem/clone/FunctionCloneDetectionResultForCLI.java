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

import gnu.trove.set.hash.TLongHashSet;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;

public class FunctionCloneDetectionResultForCLI {
	private static Logger logger = LoggerFactory.getLogger(FunctionCloneDetectionResultForCLI.class);

	public Map<String, Double> result = new HashMap<>();
	public String defaultMetric = StringResources.STR_EMPTY;
	public long searchSpace = 0;
	public long querySpace = 0;
	public String caseName = StringResources.STR_EMPTY;
	public String notes = StringResources.STR_EMPTY;
	public String truthFilePath = StringResources.STR_EMPTY;
	public double timeIndex;
	public double timeSearch;
	public String confFile;
	public List<EntryTriplet<Long, Long, Double>> cloneMape = new ArrayList<>();
	public HashSet<Long> searchSpaceVals = new HashSet<Long>();
	public HashSet<Long> querySpaceVals = new HashSet<Long>();

	public void cleanUncessary() {
		this.cloneMape.clear();
		this.searchSpaceVals.clear();
		this.querySpaceVals.clear();
	}

	public FunctionCloneDetectionResultForCLI() {
	}

	

	public FunctionCloneDetectionResultForCLI(ArrayList<EntryTriplet<Long, Long, Double>> clones,
			TLongHashSet idSearchSpace, TLongHashSet idQuerySpace, String caseName, String truthFilePath) {
		idSearchSpace.forEach(this.searchSpaceVals::add);
		idQuerySpace.forEach(this.querySpaceVals::add);
		this.searchSpace = this.searchSpaceVals.size();
		this.querySpace = this.querySpaceVals.size();
		this.cloneMape = clones;
		this.caseName = caseName;
		this.truthFilePath = truthFilePath;
	};

	private static ObjectMapper mapper = new ObjectMapper();

	public static FunctionCloneDetectionResultForCLI load(String file) throws Exception {
		FunctionCloneDetectionResultForCLI aw = mapper.readValue(new File(DmasApplication.applyDataContext(file)),
				FunctionCloneDetectionResultForCLI.class);
		return aw;
	}

	public void write(String file) {
		try {
			mapper.writeValue(new File(file), this);
		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
		}
	}

	public void writePretty(String file) {
		try {
			new File(file).getParentFile().mkdirs();
			mapper.writerWithDefaultPrettyPrinter().writeValue(new File(file), this);
		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
		}
	}

	public double defaultMetricVal() {
		if (result.containsKey(this.defaultMetric))
			return result.get(this.defaultMetric);
		else
			return -1;
	}
}
