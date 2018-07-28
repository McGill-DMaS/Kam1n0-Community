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
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;

import ca.mcgill.sis.dmas.env.StringResources;

public class IOSymHashMeta {

	public List<Long> input;
	public int hid;
	public String varName;
	public long rep;

	public IOSymHashMeta() {
	}

	public IOSymHashMeta(List<Long> input, int hid, String varName, long rep) {
		super();
		this.input = input;
		this.hid = hid;
		this.varName = varName;
		this.rep = rep;
	}

	@Override
	public String toString() {
		return "hid:" + Integer.toHexString(hid) + " (" + StringResources.JOINER_TOKEN_CSV_SPACE
				.join(input.stream().map(in -> Long.toHexString(in)).collect(Collectors.toList())) + ")";
	}

}
