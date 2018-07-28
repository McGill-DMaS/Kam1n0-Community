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

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;

public class Clean extends CLIFunction {

	private static Logger logger = LoggerFactory.getLogger(Clean.class);

	private ArgumentParser parser = ArgumentParser.create(Clean.class.getSimpleName());

	private Option op1 = parser.addOption("confFile", OpType.File, false, "the output configuration file.",
			new File("conf.xml"));

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
		return "clean data for re-generating dataset.";
	}

	@Override
	public String getCode() {
		return "clean";
	}

	@Override
	public void process(String[] args) throws Exception {

		if (!parser.parse(args)) {
			return;
		}

		File confFile = op1.getValue();
		Configuration conf = Configuration.load(confFile.getAbsolutePath());
		if (conf == null) {
			logger.error("Failed to load cofiguratio file. Run init command first to generate defaul configuration.");
			return;
		}

		ArrayList<File> files = DmasFileOperations.select(confFile.getParentFile().getAbsolutePath(),
				DmasFileOperations.REGEX_JSON, DmasFileOperations.REGEX_LOG, DmasFileOperations.REGEX_I64,
				DmasFileOperations.REGEX_IDB);
		for (File file : files) {
			logger.info("Deleting generated file: {}", file.getName());
			file.delete();
		}
	}

}
