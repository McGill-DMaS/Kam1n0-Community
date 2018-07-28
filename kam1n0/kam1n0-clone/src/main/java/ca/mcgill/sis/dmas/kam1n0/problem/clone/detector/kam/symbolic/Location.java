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

import org.apache.commons.lang3.builder.HashCodeBuilder;

import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunConfiguration;

public class Location {
	public RunConfiguration conf;
	public Long K1;
	public IOBucketMeta bk;
	public int depth = 0;

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Location) {
			Location loc = (Location) obj;
			if (loc != null && loc.conf.result.output.value.equals(conf.result.output.value) && loc.K1.equals(K1))
				return true;
			return false;
		}
		return false;
	}

	public Location(RunConfiguration conf, Long k1, IOBucketMeta bk, int depth) {
		super();
		this.conf = conf;
		this.K1 = k1;
		this.bk = bk;
		this.depth = depth;
	}

	@Override
	public int hashCode() {
		return (new HashCodeBuilder()).append(conf.result.output.value).append(K1).build();
	}
}
