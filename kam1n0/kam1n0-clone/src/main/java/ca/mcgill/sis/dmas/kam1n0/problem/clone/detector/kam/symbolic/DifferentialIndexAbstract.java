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

public abstract class DifferentialIndexAbstract {

	public abstract IOBucketCtn loadBucket(long rid, Long primaryKey, String secondaryKey);

	public abstract boolean setBucket(long rid, Long K1, String val, IOBucketCtn cnt);

	public abstract IOBucketMeta loadMeta(long rid, Long primaryKey, String secondaryKey);

	public IOBucketCtn loadBucket(long rid, Location loc) {
		return loadBucket(rid, loc.K1, loc.conf.result.output.value);
	}

	public abstract void addHidToBucket(long rid, Long K1, String val, IOSymHashMeta hid);

	public abstract void addEntry(long rid, int hid, IOEntry entry);

	public abstract boolean checkHid(long rid, int hid);

	public abstract IOSymHashCnt loadHashCnt(long rid, int hid);

	public abstract int loadHashCntCount(long rid, int hid);

	public abstract boolean dump(String folder);

	public abstract void init();

}
