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


public class IOBucketMeta {

	// meta:
	public Long K1;
	public Long newVal;
	public Long majority;
	public int count;

	public IOBucketMeta(Long k1, Long newVal, Long majority, int count) {
		super();
		K1 = k1;
		this.newVal = newVal;
		this.majority = majority;
		this.count = count;
	}

}
