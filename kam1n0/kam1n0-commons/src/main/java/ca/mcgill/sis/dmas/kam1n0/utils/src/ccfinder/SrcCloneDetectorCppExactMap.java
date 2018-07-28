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
package ca.mcgill.sis.dmas.kam1n0.utils.src.ccfinder;

import gnu.trove.map.hash.TLongObjectHashMap;

import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;

public class SrcCloneDetectorCppExactMap extends SrcCloneDetector {

	@Override
	public boolean detectClones(Iterable<SrcFunction> functions1,
			Iterable<SrcFunction> functions2) throws Exception {

		TLongObjectHashMap<SrcFunction> signatureMap = new TLongObjectHashMap<>();
		for (SrcFunction srcFunction : functions1) {
			long signature = HashUtils.constructID(
					srcFunction.fileName.getBytes(),
					srcFunction.functionName.getBytes());
			signatureMap.put(signature, srcFunction);
		}

		for (SrcFunction srcFunction : functions2) {
			long signature = HashUtils.constructID(
					srcFunction.fileName.getBytes(),
					srcFunction.functionName.getBytes());
			// find function with same signature:
			SrcFunction targetFunction = signatureMap.get(signature);
			if (targetFunction != null && targetFunction.id != srcFunction.id) {
				srcFunction.clones.add(new EntryPair<Long, Double>(
						targetFunction.id, 1.0));
				targetFunction.clones.add(new EntryPair<Long, Double>(
						srcFunction.id, 1.0));
			}
		}

		return false;
	}

	@Override
	public boolean isValid() {
		return true;
	}

}
