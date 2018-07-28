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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;

public class NgramGenerator extends SignatureGenerator {

	public NgramGenerator(int n, boolean nperm) {
		this.n = n;
		this.nperm = nperm;
	}

	int n = 3;
	boolean nperm = false;

	public ArrayList<String> generateNgram(Function function, int n) {
		ArrayList<String> sigs = new ArrayList<>();
		Iterable<List<String>> lines = Iterables.concat(function);
		Queue<String> window = new LinkedList<>();
		for (List<String> line : lines) {
			if (line.size() < 2)
				continue;
			window.add(line.get(1));
			if (window.size() == n) {
				sigs.add(Integer.toHexString(window.hashCode()));
				window.poll();
			}
		}
		return sigs;
	}

	public ArrayList<String> generateNperm(Function function, int n) {
		ArrayList<String> sigs = new ArrayList<>();
		Iterable<List<String>> lines = Iterables.concat(function);
		Queue<String> window = new LinkedList<>();
		for (List<String> line : lines) {
			if (line.size() < 2)
				continue;
			window.add(line.get(1));
			if (window.size() == n) {
				String[] perms = window.toArray(new String[window.size()]);
				Arrays.sort(perms);
				sigs.add(Integer.toHexString(Arrays.hashCode(perms)));
				window.poll();
			}
		}
		return sigs;
	}

	@Override
	public ArrayList<String> generateSignatureList(Function func) {
		if (nperm)
			return generateNperm(func, n);
		else
			return generateNgram(func, n);
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("mode",
				nperm == true ? "nperm" : "ngram", "n", n);
	}
}
