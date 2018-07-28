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

import java.util.Arrays;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;

public class SignatureGenerators {

	public static SignatureGenerator newGraphletSignatureGenerator(int K, boolean extended) {
		return new GraphletGenerator(K, extended);
	}

	public static SignatureGenerator newGraphletSignatureGeneratorColored(int K) {
		return new ColoredGraphletGenerator(K);
	}

	public static SignatureGenerator newConstantSignatureGenerator(AsmProcessor processor) {
		return new ConstantGenerator(processor);
	}

	public static SignatureGenerator newNgramGenerator(int n, boolean isNperm) {
		return new NgramGenerator(n, isNperm);
	}

	public static SignatureGenerator newCompositeGenerator(SignatureGenerator... generators) {
		return new SignatureGeneratorComposite(Arrays.asList(generators));
	}

}
