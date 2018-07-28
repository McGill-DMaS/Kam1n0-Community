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
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.CliUtils;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration.SourceProject;
import ca.mcgill.sis.dmas.kam1n0.utils.src.AsmCloneMapper.Strategy;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class Init extends CLIFunction {

	private ArgumentParser parser = ArgumentParser.create(Init.class.getSimpleName());

	private Option op1 = parser.addOption("confFile", OpType.File, false, "the output configuration file.", "conf.xml");

	private Option op2 = parser.addOption("addAll", OpType.String, false,
			"file of certain regex will be added into the project. \\.so$ is the default", "\\.so$");

	private Option opVex = parser.addOption("translateVex", OpType.Boolean, false,
			"whether to translate asm code to vex and logic graph", true);

	private Option originSrcPath = parser.addOption("originalSrcDir", OpType.String, false,
			"original source code directories, seperated by ;", StringResources.STR_EMPTY);

	private Option newSrcPath = parser.addOption("newSrcDir", OpType.String, false, "new source code directory",
			StringResources.STR_EMPTY);

	private Option cloneMappingStrategy = parser.addSelectiveOption("cloneMappingStrategy", false,
			"strategy to generate ground true mapping", Strategy.mapBySrcClone.toString(), Strategy.getStrVals());

	@Override
	public String getCategory() {
		return "dataset generation";
	}

	@Override
	public void process(String[] args) throws Exception {
		if (!parser.parse(args)) {
			return;
		}

		String oSrcPath = originSrcPath.getValue();
		String nSrcPath = newSrcPath.getValue();
		File conff = op1.getValue();
		Configuration conf = new Configuration(conff.getAbsolutePath());
		File asmDir = new File(conf.getAsmFolderDir());
		File wdir = new File(System.getProperty("user.dir"));
		if (asmDir.exists())
			DmasFileOperations.deleteRecursively(asmDir.getAbsolutePath());
		if (wdir.exists())
			for (File pdir : wdir.listFiles())
				if (pdir.isDirectory()) {

					if (DmasFileOperations.equal(asmDir, pdir))
						continue;

					SourceProject p = new SourceProject();
					p.dir = pdir.getAbsolutePath();

					if (!oSrcPath.equals(StringResources.STR_EMPTY))
						p.SourceDirectoryWhenCompile = oSrcPath;
					else
						p.SourceDirectoryWhenCompile = pdir.getAbsolutePath();

					if (!nSrcPath.equals(StringResources.STR_EMPTY))
						p.SourceDirectoryAfterCompile = nSrcPath;
					else
						p.SourceDirectoryAfterCompile = pdir.getAbsolutePath();

					CliUtils.getAllBinaries(pdir, true, Pattern.compile(op2.getValue())).stream().map(bf -> bf.getAbsolutePath())
							.forEach(p.binaries::add);

					conf.projects.add(p);
				}
		conf.translateVex = opVex.getValue();
		conf.mappingStrategy = Strategy.valueOf(cloneMappingStrategy.getValue());
		conf.save(conf.selfFile);
		conf.print();
	}

	@Override
	public ArgumentParser getParser() {
		return this.parser;
	}

	@Override
	public String getDescription() {
		return "Initialize configuration file for this directory.";
	}

	@Override
	public String getCode() {
		return "init";
	}

}
