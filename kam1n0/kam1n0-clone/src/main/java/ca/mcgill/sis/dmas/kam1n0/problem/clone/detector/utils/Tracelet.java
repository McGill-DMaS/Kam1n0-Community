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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.utils;

import java.util.ArrayList;
import java.util.List;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.tracelet.DetectorTracelet.PreSplittedBlock;

public class Tracelet extends ArrayList<EntryPair<String, ArrayList<Integer>>> {

	private static final long serialVersionUID = -3993017689991297693L;

	public Tracelet(List<PreSplittedBlock> blks) {
		blks.forEach(blk -> {
			this.addAll(blk.ins);
		});
	}

	public Tracelet() {
	}

}
