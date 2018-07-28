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
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ListMultimap;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.SrcFunctionUtils;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration.SourceProject;
import ca.mcgill.sis.dmas.kam1n0.utils.src.CPPSrcInjector;
import ca.mcgill.sis.dmas.kam1n0.utils.src.CPPSrcParser;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.src.CPPSrcParser.SrcParserType;

public class Preprocessor extends CLIFunction {

	private static Logger logger = LoggerFactory.getLogger(Preprocessor.class);

	private ArgumentParser parser = ArgumentParser.create(Preprocessor.class.getSimpleName());

	private Option op1 = parser.addOption("confFile", OpType.File, false, "the output configuration file.",
			new File("conf.xml"));

	@Override
	public String getCategory() {
		return "dataset generation";
	}
	
	@Override
	public void process(String[] args) throws Exception {
		if (!parser.parse(args)) {
			return;
		}

		File confFile = op1.getValue();
		Configuration conf = Configuration.load(confFile.getAbsolutePath());
		if (conf == null) {
			logger.error("Failed to load cofiguration file. Run init command first to generate defaul configuration.");
			return;
		}
		if (conf.projects.size() < 1) {
			logger.error("The configuration file contains no projects. Double check and run this command again.");
			return;
		}

		try {

			logger.info("Parsing functions and injecting identifiers..");
			CPPSrcParser cppParser = CPPSrcParser.getParser(SrcParserType.CPP);
			ArrayList<File> srcFiles = new ArrayList<>();
			for (SourceProject project : conf.projects) {
				File srcDir = new File(project.SourceDirectoryWhenCompile);
				if (srcDir.exists()) {
					File file = DmasApplication.createTmpFile(Integer.toString(srcDir.hashCode()) + ".src.json");
					ListMultimap<File, SrcFunction> functions = cppParser.findAll(srcDir.getAbsolutePath(), true);
					CPPSrcInjector.processFunctions(functions, cppParser);

					SrcFunctionUtils.write(functions.values(), file);
					srcFiles.add(file);
					logger.info("finished processing {}", srcDir);
				} else {
					logger.error("Nonexisted directory: {} skipping;", srcDir);
				}
			}

		} catch (Exception e) {
			logger.error("Failed to process.", e);
			return;
		}

		logger.info("finished.");
	}

	@Override
	public ArgumentParser getParser() {
		return this.parser;
	}

	@Override
	public String getDescription() {
		return "Inject source function identifier into the function body. Optional for debuging-symbol linking method.";
	}

	@Override
	public String getCode() {
		return "pre-inj";
	}

}
