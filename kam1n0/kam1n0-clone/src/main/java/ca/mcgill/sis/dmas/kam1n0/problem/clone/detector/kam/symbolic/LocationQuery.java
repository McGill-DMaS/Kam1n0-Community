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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ca.mcgill.sis.dmas.kam1n0.graph.BlockLogicWrapper;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.LaplaceBox;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunConfiguration;

public class LocationQuery {

	public LocationQuery(BlockLogicWrapper blk) {
		super();
		this.blk = blk;
	}

	public BlockLogicWrapper blk;
	public Set<String> vars = ConcurrentHashMap.newKeySet();

	public List<RunConfiguration> getConfigurations(LaplaceBox box) {
		return blk.getLogic().toConfigurable(box).getConfigurations(vars);
	}
}
