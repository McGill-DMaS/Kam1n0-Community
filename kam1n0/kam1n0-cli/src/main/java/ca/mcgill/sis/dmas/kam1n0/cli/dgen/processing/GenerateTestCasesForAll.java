package ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.CliUtils;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration.SourceProject;
import ca.mcgill.sis.dmas.kam1n0.utils.src.AsmCloneMapper.Strategy;
import ca.mcgill.sis.dmas.kam1n0.utils.src.Parser.ParserType;

/**
 * Transform libs/{bins0, bins1, bins2, ... } To
 * ds/lib-bins0-bins1/{bins0/bins0, bins1/bins1} ...
 * 
 * @author dingm
 *
 */
public class GenerateTestCasesForAll extends CLIFunction {

	private ArgumentParser parser = ArgumentParser.create(Init.class.getSimpleName());

	private static Logger logger = LoggerFactory.getLogger(GenerateTestCasesForAll.class);

	private Option binDirs = parser.addOption("targetDir", OpType.File, false,
			"the directry contains binaries of different libraries (ended with .bin)");

	private Option outDir = parser.addOption("outDir", OpType.File, false,
			"the output directry contains the source code");

	private Option minLinePerBlkOpt = parser.addOption("minLines", OpType.Integer, false,
			"minimum lines of basic block to be considered.", 1);

	private Option minBlocksOpt = parser.addOption("minBlks", OpType.Integer, false,
			"minimum basic blocks to be considered.", 1);

	private Option cloneMappingStrategy = parser.addSelectiveOption("cloneMappingStrategy", false,
			"strategy to generate ground true mapping", Strategy.mapBySrcName.toString(), Strategy.getStrVals());
	
	@Override
	public ArgumentParser getParser() {
		return this.parser;
	}

	@Override
	public String getDescription() {
		return "Generate cases based on the directory format:  binary/different-binary.bin";
	}

	@Override
	public String getCode() {
		return "genl";
	}

	@Override
	public void process(String[] args) throws Exception {
		if (!parser.parse(args)) {
			return;
		}

		String unstripped_sufix = ".unstrip";
		File bins = binDirs.getValue();

		File output_folder = outDir.getValue();
		output_folder.mkdirs();
		File output_folder_bins = new File(output_folder.getAbsolutePath() + "/binaries");
		output_folder_bins.mkdirs();

		List<File> binaries = CliUtils.getAllBinaries(bins, false, DmasFileOperations.REGEX_BIN);
		List<File> binaries_cp = binaries.stream().map(bin -> {
			try {
				File bin_to = new File(output_folder_bins.getAbsolutePath() + "/" + bin.getName());
				File bin_s = new File(bin.getAbsolutePath() + unstripped_sufix);
				File bin_s_to = new File(output_folder_bins.getAbsolutePath() + "/" + bin_s.getName());
				Files.copy(bin, bin_to);
				Files.copy(bin_s, bin_s_to);
				return bin_to;
			} catch (Exception e) {
				logger.error("Failed to process " + bin.getAbsolutePath(), e);
				return null;
			}
		}).collect(Collectors.toList());

		SourceProject p = new SourceProject();
		p.dir = output_folder_bins.getAbsolutePath();
		p.SourceDirectoryWhenCompile = StringResources.STR_EMPTY;
		p.SourceDirectoryAfterCompile = StringResources.STR_EMPTY;
		binaries_cp.stream().map(f -> f.getAbsolutePath()).forEach(p.binaries::add);

		Configuration conf = new Configuration(output_folder.getAbsolutePath() + "/conf.xml");
		conf.mappingStrategy = Strategy.valueOf(cloneMappingStrategy.getValue());
		conf.srcParserType = ParserType.unstripped;
		conf.translateVex = false;
		conf.projects.add(p);
		conf.save(conf.selfFile);

		Integer mL = minLinePerBlkOpt.getValue();
		Integer mBlk = minBlocksOpt.getValue();
		Postprocessor post = new Postprocessor();
		post.process(new String[] { "-confFile=" + conf.selfFile, "-minLines=" + mL, "-minBlks=" + mBlk });

		File ds2 = new File(output_folder.getAbsolutePath() + "-trim");
		FileUtils.copyDirectory(output_folder, ds2);
		conf.projects.stream().forEach(prj -> {
			String new_prj = (new File(prj.dir)).getAbsolutePath().replace(output_folder.getAbsolutePath(),
					ds2.getAbsolutePath());
			try {
				logger.info("Cleaning {}", new_prj);
				FileUtils.deleteDirectory(new File(new_prj));
			} catch (IOException e) {
				e.printStackTrace();
			}
		});
	}

	@Override
	public String getCategory() {
		return "dataset generation";
	}

}
