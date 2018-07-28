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

import java.util.List;

public abstract class BucketHierarchyIndex{

	public abstract void init();

	public abstract boolean close();

	public abstract boolean put(String parentBkt, String... childBkts);

	public abstract boolean put(BucketHierarchy relt);

	public abstract boolean put(List<BucketHierarchy> relts);

	public abstract boolean drop(String parentBkt);

	public abstract boolean drop(String parentBkt, String childBkt);

	public abstract BucketHierarchy get(String parentBkt);

	public abstract String nextOnTheLeft(String parentBkt, String chilBkt);

	public abstract String nextOnTheRight(String parentBkt, String chilBk);

	public abstract Integer getLeafDepth(String fullLength);

	public abstract boolean setLeafDepth(String leafId, int depth);
	
	public abstract boolean removeDepth(String fullLength);

}
