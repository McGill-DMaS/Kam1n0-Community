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
package ca.mcgill.sis.dmas.kam1n0.cli.dgen;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.LoggerFactory;

import com.google.common.collect.HashMultimap;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration.SourceProject;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.DisassemblyFactoryIDA;

public class CliUtils {

	private static org.slf4j.Logger logger = LoggerFactory.getLogger(CliUtils.class);

	public static ArrayList<File> getAllBinaries(List<File> prjs, boolean includeNoExtension, Pattern... regex) {
		return prjs.stream().flatMap(prjDir -> getAllBinaries(prjDir, includeNoExtension, regex).stream())
				.collect(Collectors.toCollection(ArrayList::new));
	}

	public static ArrayList<File> getAllBinaries(File prjDir, boolean includeNoExtension, Pattern... regexes) {
		ArrayList<File> binaries;
		try {
			binaries = DmasFileOperations.select(prjDir.getAbsolutePath(), includeNoExtension, regexes);
			return binaries;
		} catch (Exception e) {
			logger.error("Failed to get all binary files under " + prjDir, e);
		}
		return new ArrayList<>();
	}

	public static HashMultimap<SourceProject, EntryPair<BinarySurrogate, File>> diassembleSrcPrjs(
			List<SourceProject> projects) {
		HashMultimap<SourceProject, EntryPair<BinarySurrogate, File>> result = HashMultimap.create();
		projects.stream().forEach(prj -> {
			diassemble(prj.binaries.stream().map(bin -> new File(bin)).collect(Collectors.toList())).entrySet().stream()
					.map(ent -> new EntryPair<>(ent.getValue(), ent.getKey())).forEach(pair -> result.put(prj, pair));
		});
		return result;
	}

	public static Map<File, BinarySurrogate> diassemble(List<File> buidDirs) {
		return diassemble(buidDirs, DmasFileOperations.REGEX_DLL, DmasFileOperations.REGEX_EXE,
				DmasFileOperations.REGEX_A, DmasFileOperations.REGEX_SO);
	}

	public static Map<File, BinarySurrogate> diassemble(List<File> buidDirs, Pattern... regexs) {
		ArrayList<File> files = getAllBinaries(buidDirs, false, regexs);
		return files.parallelStream().peek(file -> logger.info("Disassembling {}", file))
				.collect(Collectors.toMap(file -> file, file -> DisassemblyFactory.disassembleSingle(file)));
	}

}
