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
import java.util.HashSet;
import java.util.regex.Matcher;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.SignatureGenerator;

public class ConstantGenerator extends SignatureGenerator {

	private AsmProcessor processor;

	public ConstantGenerator(AsmProcessor processor) {
		this.processor = processor;
	}

	public ArrayList<String> generateConstants(Function function) {
		HashSet<String> cons = new HashSet<>();
		function.blocks.forEach(blk -> {
			blk.getAsmLines().forEach(line -> {
				if (line.size() < 1)
					return;
				for (int i = 1; i < line.size(); ++i) {
					Matcher matcher = processor.normalizer.res.constantPattern.matcher(line.get(i));
					while (matcher.find()) {
						cons.add(matcher.group(0));
					}
				}
			});
		});
		return new ArrayList<>(cons);
	}

	@Override
	public ArrayList<String> generateSignatureList(Function func) {
		return generateConstants(func);
	}

	@Override
	public String params() {
		return "mode," + "constant";
	}

}
