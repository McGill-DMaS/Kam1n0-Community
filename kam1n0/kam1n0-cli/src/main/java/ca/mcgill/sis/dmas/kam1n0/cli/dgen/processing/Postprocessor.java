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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashMultimap;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.CliUtils;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.SrcFunctionUtils;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration.SourceProject;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.DisassemblyFactoryIDA;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectionResultForCLI;
import ca.mcgill.sis.dmas.kam1n0.utils.src.AsmCloneMapper;
import ca.mcgill.sis.dmas.kam1n0.utils.src.LinkInfo;
import ca.mcgill.sis.dmas.kam1n0.utils.src.ObjDumpParser;
import ca.mcgill.sis.dmas.kam1n0.utils.src.Parser;
import ca.mcgill.sis.dmas.kam1n0.utils.src.Parser.ParserType;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcInfo;
import ca.mcgill.sis.dmas.kam1n0.utils.src.AsmCloneMapper.Strategy;
import ca.mcgill.sis.dmas.kam1n0.utils.src.ccfinder.SrcCloneDetectorCppCCfinder;
import ca.mcgill.sis.dmas.kam1n0.vex.VEXIRBB;

public class Postprocessor extends CLIFunction {

	private static Logger logger = LoggerFactory.getLogger(Postprocessor.class);

	private ArgumentParser parser = ArgumentParser.create(Postprocessor.class.getSimpleName());

	private Option confFileOpt = parser.addOption("confFile", OpType.File, false, "the output configuration file.",
			new File("conf.xml"));

	private Option minLinePerBlkOpt = parser.addOption("minLines", OpType.Integer, false,
			"minimum lines of basic block to be considered.", 1);

	private Option minBlocksOpt = parser.addOption("minBlks", OpType.Integer, false,
			"minimum basic blocks to be considered.", 1);

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
		return "postprocessing operations to generate clone groundtruth data.";
	}

	@Override
	public String getCode() {
		return "post";
	}

	@Override
	public void process(String[] args) throws Exception {

		if (!parser.parse(args)) {
			return;
		}

		File confFile = confFileOpt.getValue();
		Configuration conf = Configuration.load(confFile.getAbsolutePath());
		if (conf == null) {
			logger.error("Failed to load cofiguration file. Run init command first to generate defaul configuration.");
			return;
		}

		List<BinarySurrogate> bins = new ArrayList<>();
		List<SrcFunction> srcFunctions = new ArrayList<>();
		LinkInfo info = new LinkInfo();

		// init
		Parser parser = Parser.getParser(conf.srcParserType);

		HashMultimap<SourceProject, EntryPair<BinarySurrogate, File>> asmFiles = CliUtils
				.diassembleSrcPrjs(conf.projects);

		for (SourceProject prj : asmFiles.keySet()) {
			Set<EntryPair<BinarySurrogate, File>> ents = asmFiles.get(prj);
			logger.info("{} binary files for project {}", ents.size(), prj.dir);
			if (conf.mappingStrategy != Strategy.mapByAsmName) {
				SrcInfo parsedInfo = parser.parseSrcFunctionAndLinkeToAssemblyFunction(prj.SourceDirectoryWhenCompile,
						prj.SourceDirectoryAfterCompile, new ArrayList<>(ents));
				info.add(parsedInfo.linkInfo);
				srcFunctions.addAll(parsedInfo.srcFuncs);
			}
			ents.stream().forEach(ent->bins.add(ent.key));
		}
		if (conf.mappingStrategy != Strategy.mapByAsmName)
			logger.info("Total linking info: {}", info.toString());

		// filter asm functions according to block size
		// filter no-source-code asm function if it is not mapByAsmName
		Integer minL = minLinePerBlkOpt.getValue();
		Integer minB = minBlocksOpt.getValue();
		srcFunctions = srcFunctions.stream().filter(src -> src.asmFuncID != -1).collect(Collectors.toList());
		bins.stream().forEach(bin->{
			bin.functions = bin.functions.stream().filter(
					func -> func.blocks.stream().mapToInt(blk -> blk.src.size()).sum() >= minL
					&& func.blocks.stream().filter(blk -> blk.asmLines().size() > 0).count() >= minB
					&& !func.blocks.get(0).src.get(0).get(1).trim().equalsIgnoreCase("extrn")
					&& !func.srcName.startsWith(".")
					&& !func.srcName.startsWith("sub_")
					&& (conf.mappingStrategy == Strategy.mapByAsmName
							|| (func.srcid != -1 || func.srcName.length() > 0)))
					.collect(Collectors.toCollection(ArrayList::new));
		});
				

		// clone generation
		logger.info("Detecting clones among asm function according to the {} strategy..", conf.mappingStrategy);
		List<EntryTriplet<Long, Long, Double>> result = conf.mappingStrategy.getInstance()
				.generateAsmCloneMap(srcFunctions, bins);
		Set<Long> vids = result.stream().flatMap(tp -> Arrays.asList(tp.value0, tp.value1).stream())
				.collect(Collectors.toSet());

		// persist clone mapping:
		logger.info("Writing ground-truth data to {} ...", conf.getGroundTruthFileDir());
		FunctionCloneDetectionResultForCLI truthResult = new FunctionCloneDetectionResultForCLI();
		truthResult.confFile = confFile.getAbsolutePath();
		// make sure the truth is in the search space
		truthResult.cloneMape = result.stream()
				// .filter(re -> vids.contains(re.value0) &&
				// vids.contains(re.value1) && re.value0 != re.value1)
				.collect(Collectors.toList());
		truthResult.caseName = confFile.getParentFile().getName();// (new
																	// File(Environment.PATH_WORKING)).getName();
		truthResult.writePretty(conf.getGroundTruthFileDir());

		// persist src function (after updated clone information in previous
		// step)
		logger.info("Writing source functions to {} ...", conf.getSrcFuncFileDir());
		SrcFunctionUtils.writePretty(
				srcFunctions.stream().filter(src -> vids.contains(src.asmFuncID)).collect(Collectors.toList()),
				new File(conf.getSrcFuncFileDir()));

		// persist asm function:
		logger.info("Writing asm functions to {} ...", conf.getAsmFolderDir());
		ObjectMapper mapper = new ObjectMapper();
		DmasFileOperations.deleteRecursivelyIfExisted(conf.getAsmFolderDir());
		for (EntryPair<BinarySurrogate, File> entry : asmFiles.values()) {
			BinarySurrogate binary = entry.key;
			binary.functions = binary.functions.stream().filter(func -> vids.contains(func.id))
					.collect(Collectors.toCollection(ArrayList::new));
			File file = new File(conf.getAsmFolderDir() + "/" + entry.value.getName() + "."
					+ entry.value.getParentFile().getName() + "." + Long.toHexString(binary.hash) + ".json");
			file.getParentFile().mkdirs();
			logger.info("##### {} total vids {}", binary.name, binary.functions.size());

//			// need to translate?
//			if (conf.translateVex) {
//				logger.info("Translating {} to vex and logic graphs.", binary.name);
//				try {
//					long curTime = System.currentTimeMillis();
//					binary.toBinary().functions.stream().flatMap(func->func.blocks.stream().map(blk->VEXIRBB.translateBlk(blk))).collect(Collectors.toList());
//					long diff = System.currentTimeMillis() - curTime;
//					logger.info("Finished. Taken {} for {} functions. Avg. {}", diff, binary.functions.size(),
//							StringResources.FORMAT_AR3D.format(diff * 1.0 / binary.functions.size()));
//					mapper.writerWithDefaultPrettyPrinter().writeValue(file, binary);
//				} catch (Exception e) {
//					logger.error("Failed to translate binary " + binary.name + " to vex.", e);
//				}
//			} else
				mapper.writerWithDefaultPrettyPrinter().writeValue(file, binary);
		}

	}

}
