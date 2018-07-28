package ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.io.Files;

import ca.mcgill.sis.dmas.env.ArgumentParser;
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
 * ds/lib-bins1-bins2/{bins1/bins1, bins2/bins2} ... or
 * ds/lib-bins0-bins1/{bins0/bins0, bins1/bins1} ...
 * ds/lib-bins0-bins2/{bins0/bins0, bins2/bins2} ... ** bins0 is identify by the
 * file contains name 'origin'
 * 
 * 
 * @author dingm
 *
 */
public class GenerateTestCasesCmb extends CLIFunction {

	private ArgumentParser parser = ArgumentParser.create(Init.class.getSimpleName());

	private static Logger logger = LoggerFactory.getLogger(GenerateTestCasesCmb.class);

	private Option targetDir = parser.addOption("targetDir", OpType.File, false,
			"the directry contains binaries of different libraries (ended with .bin)");

	private Option minLinePerBlkOpt = parser.addOption("minLines", OpType.Integer, false,
			"minimum lines of basic block to be considered.", 1);

	private Option minBlocksOpt = parser.addOption("minBlks", OpType.Integer, false,
			"minimum basic blocks to be considered.", 1);

	private Option genOpt = parser.addSelectiveOption("gen", false, "how the combination is generated.", "combination",
			Arrays.asList("combination", "against"));

	private Option genOptAgn = parser.addOption("gen-key", OpType.String, false,
			"The keyword usded for the 'against' mode", "against");

	private Option cloneMappingStrategy = parser.addSelectiveOption("cloneMappingStrategy", false,
			"strategy to generate ground true mapping.", Strategy.mapBySrcName.toString(), Strategy.getStrVals());

	@Override
	public ArgumentParser getParser() {
		return this.parser;
	}

	@Override
	public String getDescription() {
		return "Generate cases based on the directory format: binary/different-binary.bin";
	}

	@Override
	public String getCode() {
		return "genlcmb";
	}

	@Override
	public void process(String[] args) throws Exception {
		if (!parser.parse(args)) {
			return;
		}

		String sufix = "\\.bin$";
		String unstripped_sufix = ".unstrip";
		File target = targetDir.getValue();
		File ds = new File(target.getParentFile().getAbsolutePath() + "/ds");
		ds.mkdirs();

		// disassemble if not done yet
		// CliUtils.diassemble(CliUtils.getAllBinaries(target, false, sufix));

		// move file and organize into test cases
		List<Configuration> confs = new ArrayList<>();
		for (File lib : target.listFiles()) {
			List<File> binaries = CliUtils.getAllBinaries(lib, false, Pattern.compile(sufix));
			List<String> names = caseNames(binaries);
			List<Integer> inds = IntStream.range(0, binaries.size()).mapToObj(val -> val).collect(Collectors.toList());
			List<List<Integer>> cases;
			if (genOpt.getValue().equals("combination"))
				cases = DmasCollectionOperations.combination(inds, 2);
			else {
				cases = new ArrayList<>();
				String key = genOptAgn.getValue();
				Optional<File> optlFile = binaries.stream().filter(bin -> bin.getName().contains(key)).findFirst();
				if (!optlFile.isPresent()) {
					logger.error("For the against mode, we need a file target file but it is not there: key {}", key);
					return;
				}
				File agnTarget = optlFile.get();
				int agnIndx = binaries.indexOf(agnTarget);
				for (int i = 0; i < binaries.size(); ++i)
					if (i != agnIndx)
						cases.add(Arrays.asList(agnIndx, i));
			}

			// required if parsing objdump files.
			// File src_dir_file = new File(lib.getAbsolutePath() +
			// "/original_src_dir.txt");
			// String o_src_dir;
			// if (src_dir_file.exists())
			// o_src_dir = Files.readFirstLine(new File(lib.getAbsolutePath() +
			// "/original_src_dir.txt"),
			// Charsets.UTF_8);
			// else
			// o_src_dir = StringResources.STR_EMPTY;

			logger.info("Processing {} for {}", cases, lib.getName());

			for (List<Integer> cas : cases) {

				String casName = StringResources.JOINER_DASH
						.join(cas.stream().map(ind -> names.get(ind)).collect(Collectors.toList()));
				File casFolder = new File(ds.getAbsoluteFile() + "/" + lib.getName() + "-" + casName);
				casFolder.mkdir();

				List<File> subFolders = new ArrayList<>();
				List<SourceProject> subProjects = new ArrayList<>();
				for (Integer binInd : cas) {
					File subFolder = new File(casFolder.getAbsolutePath() + "/" + names.get(binInd));
					subFolder.mkdir();
					subFolders.add(subFolder);

					File bin = binaries.get(binInd);
					List<String> copied_binaries = DmasFileOperations.copyAllFiles(//
							bin.getParentFile().getAbsolutePath(), //
							subFolder.getAbsolutePath(),
							file -> file.getName()
									.startsWith(bin.getName().substring(0, bin.getName().lastIndexOf('.'))), //
							file -> file.getName().equals(bin.getName())//
					).stream().map(file -> file.getAbsolutePath()).collect(Collectors.toList());

					// File bin_to = new File(subFolder.getAbsolutePath() + "/" + bin.getName());
					// File bin_s = new File(bin.getAbsolutePath() + unstripped_sufix);
					// File bin_s_to = new File(subFolder.getAbsolutePath() + "/" +
					// bin_s.getName());
					// Files.copy(bin, bin_to);
					// Files.copy(bin_s, bin_s_to);

					SourceProject p = new SourceProject();
					p.dir = subFolder.getAbsolutePath();
					p.SourceDirectoryWhenCompile = StringResources.STR_EMPTY;
					p.SourceDirectoryAfterCompile = StringResources.STR_EMPTY;
					p.binaries.addAll(copied_binaries);
					subProjects.add(p);
				}

				// generate init file for each case
				Configuration conf = new Configuration(casFolder.getAbsolutePath() + "/conf.xml");
				conf.mappingStrategy = Strategy.valueOf(cloneMappingStrategy.getValue());
				conf.srcParserType = ParserType.unstripped;
				conf.translateVex = false;
				conf.projects.addAll(subProjects);
				conf.save(conf.selfFile);
				confs.add(conf);
			}
		}

		Integer mL = minLinePerBlkOpt.getValue();
		Integer mBlk = minBlocksOpt.getValue();
		for (Configuration conf : confs) {
			Postprocessor post = new Postprocessor();
			post.process(new String[] { "-confFile=" + conf.selfFile, "-minLines=" + mL, "-minBlks=" + mBlk });
		}

		File ds2 = new File(ds.getAbsolutePath() + "-trim");
		FileUtils.copyDirectory(ds, ds2);
		confs.stream().flatMap(conf -> conf.projects.stream()).forEach(prj -> {
			String new_prj = (new File(prj.dir)).getAbsolutePath().replace(ds.getAbsolutePath(), ds2.getAbsolutePath());
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

	private static List<String> caseNames(List<File> bins) {
		if (bins.size() < 1)
			return new ArrayList<>();
		List<String[]> parts = bins.stream().map(bin -> bin.getName().split("\\-")).collect(Collectors.toList());
		int ind = -1;
		for (int i = 0; i < parts.size(); ++i)
			if (ind == -1)
				ind = parts.get(i).length;
			else if (ind != parts.get(i).length)
				logger.error("File names should have same parts. {} has {} parts but others have {} parts.",
						bins.get(i).getName(), parts.get(i).length, ind);
		ArrayList<Integer> invalidInds = new ArrayList<>();
		for (int i = 0; i < ind; ++i) {
			boolean valid = true;
			String ele = parts.get(0)[i];
			for (String[] part : parts)
				if (!part[i].equals(ele)) {
					valid = false;
					break;
				}
			if (!valid)
				invalidInds.add(i);
		}
		List<String> names = new ArrayList<>();
		for (String[] part : parts) {
			String name = StringResources.JOINER_DASH
					.join(invalidInds.stream().map(ivind -> part[ivind]).collect(Collectors.toList()));
			names.add(name);
		}
		return names;
	}

}
