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

import java.io.File;
import java.util.HashMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

public class DifferentialIndexRam extends DifferentialIndexAbstract {

	public Table<Long, Long, HashMap<String, IOBucketCtn>> data = HashBasedTable.create();
	public Table<Long, Integer, IOSymHashCnt> hidTable = HashBasedTable.create();

	@Override
	public IOBucketCtn loadBucket(long rid, Long primaryKey, String secondaryKey) {
		HashMap<String, IOBucketCtn> subMap = data.get(rid, primaryKey);
		if (subMap == null)
			return null;
		return subMap.get(secondaryKey);
	}

	@Override
	public boolean setBucket(long rid, Long K1, String val, IOBucketCtn cnt) {
		HashMap<String, IOBucketCtn> subMap = data.get(rid, K1);
		if (subMap == null) {
			subMap = new HashMap<>();
			data.put(rid, K1, subMap);
		}
		subMap.put(val, cnt);
		return true;
	}

	@Override
	public IOBucketMeta loadMeta(long rid, Long primaryKey, String secondaryKey) {
		HashMap<String, IOBucketCtn> subMap = data.get(rid, primaryKey);
		if (subMap == null)
			return null;
		return subMap.get(secondaryKey);
	}

	@Override
	public void addHidToBucket(long rid, Long K1, String val, IOSymHashMeta hid) {
		HashMap<String, IOBucketCtn> subMap = data.get(rid, K1);
		if (subMap == null) {
			subMap = new HashMap<>();
			data.put(rid, K1, subMap);
		}
		IOBucketCtn bk = subMap.get(val);
		if (bk == null) {
			bk = new IOBucketCtn(null, null, null, 0);
			subMap.put(val, bk);
		}
		bk.entries.add(hid);
		bk.count++;
	}

	@Override
	public void addEntry(long rid, int hid, IOEntry entry) {
		IOSymHashCnt cnt = hidTable.get(rid, hid);
		if (cnt == null) {
			cnt = new IOSymHashCnt(hid);
			this.hidTable.put(rid, hid, cnt);
		}
		cnt.entries.add(entry);
	}

	@Override
	public boolean checkHid(long rid, int hid) {
		return hidTable.contains(rid, hid);
	}

	@Override
	public IOSymHashCnt loadHashCnt(long rid, int hid) {
		return hidTable.get(rid, hid);
	}

	@Override
	public int loadHashCntCount(long rid, int hid) {
		return hidTable.get(rid, hid).entries.size();
	}

	@Override
	public boolean dump(String folder) {
		File f1 = new File(folder + "//htable.json");
		File f2 = new File(folder + "//btable.json");
		try {
			ObjectMapper mapper = new ObjectMapper();
			mapper.writerWithDefaultPrettyPrinter().writeValue(f1, this.hidTable);
			mapper.writerWithDefaultPrettyPrinter().writeValue(f2, this.data);
			return true;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public void init() {
	}

}
