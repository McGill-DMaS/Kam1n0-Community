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
package ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.CliUtils;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.utils.src.Parser;
import ca.mcgill.sis.dmas.kam1n0.utils.src.Parser.ParserType;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcInfo;

public class PostprocessorForNameTagger extends CLIFunction {

	private static Logger logger = LoggerFactory.getLogger(PostprocessorForNameTagger.class);

	private ArgumentParser parser = ArgumentParser.create(PostprocessorForNameTagger.class.getSimpleName());

	private Option dataPath = parser.addOption("dataPath", OpType.File, false,
			"the path contains bainaries and their debug symbol file.");

	@Override
	public String getCategory() {
		return "dataset generation";
	}

	@Override
	public ArgumentParser getParser() {
		return this.parser;
	}

	@Override
	public String getDescription() {
		return "operations to generate clone groundtruth data. (rename asm func with src name)";
	}

	@Override
	public String getCode() {
		return "post-nt";
	}

	@Override
	public void process(String[] args) throws Exception {

		if (!parser.parse(args)) {
			return;
		}

		File data = dataPath.getValue();
		tag(data, DmasFileOperations.REGEX_O, DmasFileOperations.REGEX_BIN);

	}

	public static void tag(File data, Pattern ... ptns) throws Exception {
		// init
		Parser parser = Parser.getParser(ParserType.unstripped);
		ObjectMapper mapper = new ObjectMapper();

		DmasFileOperations.select(data.getAbsolutePath(), ptns).parallelStream().forEach(file -> {
			BinarySurrogate bin = DisassemblyFactory.disassembleSingle(file);
			parser.parseSrcFunctionAndLinkeToAssemblyFunction(null, null, new EntryPair<>(bin, file));
			bin.functions.stream().forEach(func -> func.name = func.srcName);
			File taggedFile = new File(file.getAbsolutePath() + ".tagged");
			logger.info("Writing {}", taggedFile);
			try {
				mapper.writerWithDefaultPrettyPrinter().writeValue(taggedFile, bin);
			} catch (Exception e) {
				logger.info("");
			}
		});
	}

}
