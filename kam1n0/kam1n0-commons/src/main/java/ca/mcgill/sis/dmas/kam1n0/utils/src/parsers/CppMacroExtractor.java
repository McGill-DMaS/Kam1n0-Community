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
package ca.mcgill.sis.dmas.kam1n0.utils.src.parsers;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco.CppReader;
import ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco.Macro;

public class CppMacroExtractor {

	@SuppressWarnings("unused")
	public static Map<String, Macro> extractMacros(String filePath,
			List<String> includedPaths) throws Exception {
		FileReader r = new FileReader(filePath);
		CppReader p = new CppReader(r);
		p.getPreprocessor().setSystemIncludePath(includedPaths);
		BufferedReader b = new BufferedReader(p);
		String line = null;
		int count = 0;
		while ((line = b.readLine()) != null) {
			count++;
		}
		b.close();
		return p.getPreprocessor().macros;
	}
	
	public static Map<String, String> extractSymbolicMacros(String filePath,
			List<String> includedPaths) throws Exception {
		Map<String, Macro> marcos = extractMacros(filePath, includedPaths);
		HashMap<String, String> hashMap = new HashMap<>();
		for (Entry<String, Macro> entry : marcos.entrySet()) {
			if(!entry.getValue().isFunctionLike() && !entry.getValue().getText().contains("(") && !entry.getValue().getText().contains("(")){
				hashMap.put(entry.getValue().getName().trim(), entry.getValue().getText().trim());
			}
		}
		return hashMap;
	}
	

}
