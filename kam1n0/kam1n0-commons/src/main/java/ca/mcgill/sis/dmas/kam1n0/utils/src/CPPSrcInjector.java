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
package ca.mcgill.sis.dmas.kam1n0.utils.src;

import gnu.trove.map.hash.TIntObjectHashMap;
import java.io.File;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ListMultimap;

import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;

public class CPPSrcInjector {

	private static Logger logger = LoggerFactory.getLogger(CPPSrcInjector.class);

	public static class IncCounter {
		public int val = 0;

		public void inc() {
			val++;
		}
	}

	public static boolean injectFunctionIdentifier(File file,
			List<SrcFunction> functions, CPPSrcParser parser) {
		if (!file.exists()) {
			logger.error("Input file nonexisted {}", file.getAbsoluteFile());
			return false;
		}

		try {
			TIntObjectHashMap<SrcFunction> set = new TIntObjectHashMap<SrcFunction>();
			for (SrcFunction function : functions) {
				set.put(function.s_index, function);
			}
			Lines lines = Lines.fromFileFullyCached(file.getAbsolutePath());
			String path = file.getAbsolutePath();
			file.delete();
			LineSequenceWriter writer = Lines.getLineWriter(path, false);
			int count = 0;
			int offset = 0;
			int limit = 0;
			boolean waiteForScope = false;
			for (String string : lines) {
				if (set.containsKey(count)) {
					waiteForScope = true;
					offset = count;
					limit = set.get(count).content.size();
				}

				if (count - offset >= limit)
					waiteForScope = false;

				if (waiteForScope && string.contains("{")) {
					SrcFunction cfunction = set.get(offset);
					String hex = Integer.toHexString(Long
							.hashCode(cfunction.id));
					
					String declaration = parser.declareVaraible(
							"injectedDmasVar" + hex, "0x" + hex);
					// update: if ! contains injection : inject declaration
					if (!string.contains("injectedDmasVar")) {
						string = string.replaceFirst("\\{", "{ " + declaration);
						cfunction.content.set(count - offset, string);
					}else{
						string = parser.replaceDelcaration(string, declaration);
						cfunction.content.set(count - offset, string);
					}
					cfunction.injectedID = hex;
					waiteForScope = false;
				}

				writer.writeLine(string);
				count++;
			}
			writer.close();
			return true;
		} catch (Exception e) {
			logger.error(
					"Failed to parse the file.. " + file.getAbsolutePath(), e);
			return false;
		}
	}

	/**
	 * 
	 * @param projectFoldernput
	 *            folder is the folder for project
	 * @param outputFolder
	 *            output folder is the folder for outputing all the extracted
	 *            functions with injected identifier
	 * @param srcCodeType
	 * @return
	 */
	public static boolean processFunctions(
			ListMultimap<File, SrcFunction> functions, CPPSrcParser parser) {

		boolean result = true;
		for (File srcFile : functions.keySet()) {
			result &= injectFunctionIdentifier(srcFile, functions.get(srcFile),
					parser);
		}
		return result;
	}

	public static void main(String[] args) {

	}
}
