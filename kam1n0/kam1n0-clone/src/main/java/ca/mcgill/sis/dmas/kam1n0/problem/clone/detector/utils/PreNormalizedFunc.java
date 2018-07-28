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
import java.util.Iterator;
import java.util.List;

import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragmentNormalized;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class PreNormalizedFunc implements Iterable<List<String>> {
	public Function originFunc;
	public ArrayList<List<String>> lines = new ArrayList<>();

	public PreNormalizedFunc(Function func, AsmLineNormalizer normalizer) {
		originFunc = func;
		for (List<String> line : Iterables.concat(func)) {
			List<String> tokens = normalizer.tokenizeAsmLine(line);
			if (tokens.size() < 1)
				continue;
			lines.add(tokens);
		}
	}

	public ArrayList<Region> subRegions(int winSize, int step) {
		ArrayList<Region> regions = new ArrayList<>();
		for (int i = 0; i <= lines.size() - winSize; i += step) {
			regions.add(new Region(i, i + winSize));
		}
		return regions;
	}

	public class Region extends AsmFragmentNormalized {
		public int from = 0;
		public int to = 0;
		public int count = 0;

		public Region(int from, int to) {
			super(lines.subList(from, to));
			this.from = from;
			this.to = to;
		}

		public Iterator<List<String>> iterator() {
			return this.asmLines.iterator();
		}

	}

	@Override
	public Iterator<List<String>> iterator() {
		return lines.iterator();
	}
}
