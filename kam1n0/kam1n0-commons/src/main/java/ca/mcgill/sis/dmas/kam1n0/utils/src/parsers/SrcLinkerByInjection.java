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

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashMultimap;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BlockSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunctionUtils;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunctionUtils.SrcFunctions;

public class SrcLinkerByInjection {

	private static Logger logger = LoggerFactory.getLogger(SrcLinkerByInjection.class);

	private static Pattern injectionPattern = Pattern.compile("[0]{0,1}([0-9a-fA-F]{8})[hH]");

	/**
	 * return list of clones between assembly functions asm function id -> asm
	 * function id, asm function id, ...
	 * 
	 * @param functions
	 * @param assemblyFunctions
	 * @return
	 */
	public static void linkToAssemblySurrogateOriginal(List<SrcFunction> functions,
			List<FunctionSurrogate> assemblyFunctions) {

		HashMap<String, SrcFunction> srcFunctionInjectionIDMap = new HashMap<>();
		for (SrcFunction srcFunction : functions) {
			srcFunctionInjectionIDMap.put(srcFunction.injectedID.toLowerCase(), srcFunction);
		}

		int f_matches = 0;
		int b_matches = 0;
		int count = 0;
		HashSet<String> unmatchedKey = new HashSet<>();
		for (FunctionSurrogate asmFunction : assemblyFunctions) {

			// find all possible injected ids.
			HashMap<String, BlockSurrogate> injectkeyBlockMap = new HashMap<>();
			for (BlockSurrogate asmBlock : asmFunction.blocks) {
				for (List<String> line : asmBlock) {
					for (String tkn : line) {
						Matcher matcher = injectionPattern.matcher(tkn);
						if (matcher.find()) {
							String id = matcher.group(1).toLowerCase();
							// if srcfunctions contain such key
							if (srcFunctionInjectionIDMap.containsKey(id))
								injectkeyBlockMap.put(id, asmBlock);
						}
					}
				}
			}

			// linking:
			if (injectkeyBlockMap.size() == 1) {
				// function - function exact matched
				String key = injectkeyBlockMap.keySet().iterator().next();
				if (srcFunctionInjectionIDMap.containsKey(key)) {
					SrcFunction srcFunction = srcFunctionInjectionIDMap.get(key);
					srcFunction.asmFuncID = asmFunction.id;
					asmFunction.srcid = srcFunction.id;
					f_matches++;

				} else {
					unmatchedKey.add(key);
					count++;
				}
			} else if (injectkeyBlockMap.size() > 1) {
				// ids in an assembly function come fromm different src function
				// function - block matched
				for (String key : injectkeyBlockMap.keySet()) {
					if (srcFunctionInjectionIDMap.containsKey(key)) {
						SrcFunction srcFunction = srcFunctionInjectionIDMap.get(key);
						BlockSurrogate asmBlock = injectkeyBlockMap.get(key);
						srcFunction.asmBlockID = asmBlock.id;
						asmBlock.srcid = srcFunction.id;
						b_matches++;
					} else {
						unmatchedKey.add(key);
						count++;
					}
				}
			}
		}

		logger.info("total function-function exact matches: {}; block-function matches: {}; total srcFunctions {};",
				f_matches, b_matches, srcFunctionInjectionIDMap.size());

		logger.info("unmatched keys: {}, count: {}", unmatchedKey.toString(), count);
		return;
	}

	/**
	 * return list of clones between assembly functions asm function id -> asm
	 * function id, asm function id, ...
	 * 
	 * @param functions
	 * @param assemblyFunctions
	 * @return
	 */
	public static void linkToAssemblySurrogateConsiderInlines(List<SrcFunction> functions,
			List<FunctionSurrogate> assemblyFunctions) {

		HashMap<String, SrcFunction> iid_srcFunction = new HashMap<>();
		for (SrcFunction srcFunction : functions) {
			if (!srcFunction.injectedID.isEmpty())
				iid_srcFunction.put(srcFunction.injectedID.toLowerCase(), srcFunction);
		}

		HashMultimap<String, FunctionSurrogate> iid_asm_map = HashMultimap.create();
		HashMultimap<FunctionSurrogate, String> asm_iid_map = HashMultimap.create();
		for (FunctionSurrogate asmFunction : assemblyFunctions) {
			for (BlockSurrogate asmBlock : asmFunction.blocks) {
				for (List<String> line : asmBlock) {
					for (String tkn : line) {
						Matcher matcher = injectionPattern.matcher(tkn);
						if (matcher.find()) {
							String iid = matcher.group(1).toLowerCase();
							// if srcfunctions contain such key
							if (iid_srcFunction.containsKey(iid)) {
								iid_asm_map.put(iid, asmFunction);
								asm_iid_map.put(asmFunction, iid);
							}
						}
					}
				}
			}
		}

		// now we have:
		// injectid -> srcFunction
		// injectid -> asmFunctions
		// here we look for one-to-one exact mapping.
		HashSet<FunctionSurrogate> unmatched_asmf = new HashSet<>();
		HashSet<String> matched_iids = new HashSet<>();
		for (FunctionSurrogate asmFunction : asm_iid_map.keySet()) {

			Set<String> iids = asm_iid_map.get(asmFunction);

			if (iids.size() == 1) {
				// exact one->one mapping ?
				String iid = iids.iterator().next();
				Set<FunctionSurrogate> asmfs = iid_asm_map.get(iid);
				if (asmfs.size() == 1 && asmfs.iterator().next().id == asmFunction.id) {
					SrcFunction srcFunction = iid_srcFunction.get(iid);
					srcFunction.asmFuncID = asmFunction.id;
					asmFunction.srcid = srcFunction.id;
					asmFunction.srcName = srcFunction.functionName;
					matched_iids.add(iid);
				} else {
					unmatched_asmf.add(asmFunction);
				}
			} else {
				unmatched_asmf.add(asmFunction);
			}
		}

		// process the rest asm functions
		boolean updated = false;
		int iteration = 0;
		do {
			iteration++;
			Iterator<FunctionSurrogate> ite = unmatched_asmf.iterator();
			while (ite.hasNext()) {
				FunctionSurrogate asmFunction = ite.next();
				Set<String> iids = asm_iid_map.get(asmFunction);
				HashSet<String> v_iids = new HashSet<>();
				for (String iid : iids) {
					if (!matched_iids.contains(iid))
						v_iids.add(iid);
				}
				// look for exact one->one mapping
				if (v_iids.size() == 1) {
					String iid = iids.iterator().next();
					Set<FunctionSurrogate> asmfs = iid_asm_map.get(iid);
					HashSet<FunctionSurrogate> v_asmfs = new HashSet<>();
					for (FunctionSurrogate asmf : asmfs) {
						if (unmatched_asmf.contains(asmf))
							v_asmfs.add(asmf);
					}
					if (v_asmfs.size() == 1 && v_asmfs.iterator().next().id == asmFunction.id) {
						SrcFunction srcFunction = iid_srcFunction.get(iid);
						srcFunction.asmFuncID = asmFunction.id;
						asmFunction.srcid = srcFunction.id;
						asmFunction.srcName = srcFunction.functionName;
						matched_iids.add(iid);
						updated = true;
						ite.remove();
					}
				}
			}
		} while (!unmatched_asmf.isEmpty() && updated);

		logger.info(
				"total asm function: {}; total unmatched asm function (but has injected pattern): {}; total matched asm function: {}; total srcFunctions {}; iterations {}.",
				assemblyFunctions.size(), unmatched_asmf.size(), asm_iid_map.keySet().size() - unmatched_asmf.size(),
				iid_srcFunction.size(), iteration);

	}

	public static void main(String[] args) throws Exception {
		BinarySurrogate surrogate = BinarySurrogate
				.load("F:\\Kam1n0\\SqlLite\\asms\\sqlite3.dll.96222d4142c864eb.json");

		SrcFunctions srcFunctions = SrcFunctionUtils.getSrcFunctions(new File("F:\\Kam1n0\\SqlLite\\test.json"));
		ArrayList<SrcFunction> srcFunctionList = new ArrayList<>();
		for (SrcFunction srcFunction : srcFunctions) {
			srcFunctionList.add(srcFunction);
		}
		ArrayList<FunctionSurrogate> asmFunctions = new ArrayList<>();
		for (FunctionSurrogate asmFcuntion : surrogate) {
			asmFunctions.add(asmFcuntion);
		}
		linkToAssemblySurrogateConsiderInlines(srcFunctionList, asmFunctions);

	}

}
