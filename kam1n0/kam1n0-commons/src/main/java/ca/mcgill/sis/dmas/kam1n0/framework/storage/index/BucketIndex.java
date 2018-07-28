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
package ca.mcgill.sis.dmas.kam1n0.framework.storage.index;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import org.apache.spark.api.java.JavaRDD;

public abstract class BucketIndex {

	public abstract void init();

	public abstract boolean close();

	public abstract boolean put(String bucketID, long value);

	public abstract boolean put(String bucketID, HashSet<Long> values);

	public abstract boolean put(ArrayList<Bucket> bucketMap);

	public abstract boolean drop(String bucketID, long value);
	
	public abstract boolean drop(String bucketID);

	public abstract List<Bucket> fetch(List<String> bucketIDs);
	
	public abstract Bucket fetch(String bucketIDs);
	
	public abstract JavaRDD<Bucket> fetchAsRDD(List<String> bucketID);
	
	
}
