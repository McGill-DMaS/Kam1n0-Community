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
package ca.mcgill.sis.dmas.kam1n0.symbolic.run;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.symbolic.Symbol;

public class RunConfiguration {

	private static Logger logger = LoggerFactory.getLogger(RunConfiguration.class);

	public List<Assignment> inputAssignments = new ArrayList<>();
	public Symbol outputSymbol;
	public RunResult result;
	public RunConfigurable configurable;

	public RunConfiguration setValue(long val) {
		inputAssignments.forEach(in -> in.value = Long.toHexString(val));
		return this;
	}

	public List<Long> getValue() {
		return inputAssignments.stream().map(assign -> Long.parseUnsignedLong(assign.value, 16))
				.collect(Collectors.toList());
	}

	public RunConfiguration setValue(List<Long> vals) {
		if (vals.size() != inputAssignments.size())
			logger.error("Size unmatched when setting input symobls to concrete values.");
		for (int i = 0; i < vals.size(); ++i)
			inputAssignments.get(i).value = Long.toHexString(vals.get(i));
		return this;
	}

	public RunResult run(LaplaceBox box) {
		return box.run(this);
	}

	public Symbol subtitute() {
		return outputSymbol.substitue(inputAssignments);
	}
	
	
	public RunConfiguration copy() {
		RunConfiguration conf = new RunConfiguration();
		conf.outputSymbol = outputSymbol;
		conf.result = null;
		conf.configurable = configurable;
		conf.inputAssignments = inputAssignments.stream().map(Assignment::copy).collect(Collectors.toList());
		return conf;

	}
}
