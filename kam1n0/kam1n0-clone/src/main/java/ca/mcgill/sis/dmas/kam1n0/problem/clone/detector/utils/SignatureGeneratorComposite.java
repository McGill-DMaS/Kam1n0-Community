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

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;

public class SignatureGeneratorComposite extends SignatureGenerator {

	public SignatureGeneratorComposite(List<SignatureGenerator> generators) {
		this.generators = generators;
	}

	List<SignatureGenerator> generators;

	@Override
	public ArrayList<String> generateSignatureList(Function func) {
		ArrayList<String> sigs = new ArrayList<>();
		generators.forEach(gen -> gen.generateSignatureList(func).forEach(sig -> sigs.add(sig)));
		return sigs;
	}

	@Override
	public String params() {
		ArrayList<String> pm = new ArrayList<>();
		generators.forEach(gen -> pm.add(gen.params()));
		return StringResources.JOINER_TOKEN_CSV.join(pm);
	}

}
