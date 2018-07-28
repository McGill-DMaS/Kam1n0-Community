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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketHierarchy;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.index.BucketHierarchyIndex;

public class BucketHierachyIndexRAM extends BucketHierarchyIndex {

	public HashMap<String, ArrayList<String>> cache = new HashMap<>();
	public HashMap<String, Integer> depth = new HashMap<>();

	@Override
	public void init() {
		cache = new HashMap<>();
		depth = new HashMap<>();
	}

	@Override
	public boolean close() {
		cache = null;
		depth = null;
		return true;
	}

	@Override
	public boolean put(String parentBkt, String... childBkts) {
		ArrayList<String> ls = new ArrayList<>(Arrays.asList(childBkts));
		ls.sort(String::compareTo);
		cache.put(parentBkt, ls);
		return true;
	}

	@Override
	public boolean put(BucketHierarchy relt) {
		relt.children.sort(String::compareTo);
		cache.put(relt.parent, relt.children);
		return true;
	}

	@Override
	public boolean put(List<BucketHierarchy> relts) {
		relts.forEach(relt -> put(relt));
		return true;
	}

	@Override
	public boolean drop(String parentBkt) {
		cache.remove(parentBkt);
		return true;
	}

	@Override
	public boolean drop(String parentBkt, String childBkt) {
		List<String> ls = cache.get(parentBkt);
		if (ls != null) {
			int ind = Collections.binarySearch(ls, childBkt);
			if (ind >= 0) {
				ls.remove(ind);
			}
			if (ls.size() == 0) {
				cache.remove(parentBkt);
			}
		}
		return true;
	}

	@Override
	public BucketHierarchy get(String parentBkt) {
		BucketHierarchy bie = new BucketHierarchy();
		bie.parent = parentBkt;
		bie.children = cache.get(parentBkt);
		if (bie.children != null)
			return bie;
		else
			return null;
	}

	@Override
	public String nextOnTheLeft(String parentBkt, String chilBkt) {
		List<String> ls = cache.get(parentBkt);
		if (ls == null)
			return null;
		int ind = Collections.binarySearch(ls, chilBkt);
		if (ind >= 1)
			return ls.get(ind - 1);
		else
			return null;
	}

	@Override
	public String nextOnTheRight(String parentBkt, String chilBkt) {
		List<String> ls = cache.get(parentBkt);
		if (ls == null)
			return null;
		int ind = Collections.binarySearch(ls, chilBkt);
		if (ind >= 0 && ind < ls.size() - 1)
			return ls.get(ind + 1);
		else
			return null;
	}

	@Override
	public Integer getLeafDepth(String fullLength) {
		return depth.get(fullLength);
	}

	@Override
	public boolean setLeafDepth(String leafId, int depth) {
		this.depth.put(leafId, depth);
		return true;
	}

	@Override
	public boolean removeDepth(String fullLength) {
		this.depth.remove(fullLength);
		return true;
	}

	private static Logger logger = LoggerFactory.getLogger(BucketHierachyIndexRAM.class);

	@Override
	public String toString() {
		ObjectMapper mapper = new ObjectMapper();
		try {
			return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			logger.error("Failed to serialize this object", e);
			return StringResources.STR_EMPTY;
		}
	}

}
