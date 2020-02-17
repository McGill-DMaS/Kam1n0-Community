package ca.mcgill.sis.dmas.kam1n0.cli;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.Exp;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.DetectorsKam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep.Asm2VecCloneDetectorIntegration;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;
import scala.Tuple2;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.graph.Kam1n0SymbolicModule;

public class Batch {
	private static Logger logger = LoggerFactory.getLogger(Batch.class);

	public static class HeatMapData {
		public double[][] similarity;
		public List<String> labels;
	}

	public static class EntryDetails {

	}

	public static class Result {
		public Map<String, HeatMapData> contents = new HashMap<>();
		public Map<String, String> templates = new HashMap<>();
		public Map<String, EntryDetails> details = new HashMap<>();

		public void put(String key, double[][] data, List<String> labels) {
			HeatMapData hm = new HeatMapData();
			hm.similarity = data;
			hm.labels = labels;
			contents.put(key, hm);
			templates.put(key, "HeatMap");
		}
	}

	public static enum Model {
		asm2vec, asmbin2vec, sym1n0, asmclone,
	}

	public static void process(String path, String resPath, SparkInstance spark, Model choice) throws Exception {

		logger.info("loading data...");
		Counter fc = Counter.zero();
		List<Binary> bins = Files.walk(Paths.get(path)).filter(Files::isRegularFile).parallel().map(p -> {
			BinarySurrogate b;
			try {
				if (p.toFile().getName().endsWith(".json")) {
					b = BinarySurrogate.load(p.toFile());
					b.processRawBinarySurrogate();
				} else {
					b = DisassemblyFactory.disassembleSingle(p.toFile());
				}
				fc.inc(b.functions.size());
				Binary bin = b.toBinary();
				bin.binaryName = p.toFile().getName().split("\\.")[0] + '-' + b.md5.substring(0, 6);

				return bin;
			} catch (Exception e) {
				logger.error("Failed to load " + p, e);
				return null;
			}
		}).collect(Collectors.toList());
		logger.info("{} bins {} funcs.", bins.size(), fc.getVal());
		bins.sort((a, b) -> a.binaryName.compareTo(b.binaryName));

		if (bins.size() < 1)
			return;

		Architecture atype = bins.get(0).architecture;

		Map<String, Integer> labelMap = IntStream.range(0, bins.size()).mapToObj(ind -> ind)
				.collect(Collectors.toMap(ind -> bins.get(ind).binaryName, ind -> ind));
		List<String> labels = bins.stream().map(b -> b.binaryName).collect(Collectors.toList());

		AsmObjectFactory ram = AsmObjectFactory.init(spark, "batch-mode", "kam1n0");
		FunctionCloneDetector model = null;
		if (choice == Model.asm2vec) {
			Asm2VecNewParam param = new Asm2VecNewParam();
			param.optm_iteration = 20;
			param.vec_dim = 100;
			param.optm_parallelism = 5;
			model = new Asm2VecCloneDetectorIntegration(ram, param);
		} else if (choice == Model.asmclone) {
			model = DetectorsKam.getLshAdaptiveSubGraphFunctionCloneDetectorRam(spark, "batch-platform-tmp",
					"batch-tmp", atype.type);
		} else if (choice == Model.sym1n0) {
			Kam1n0SymbolicModule.setup();
			model = DetectorsKam.getSymbolicSubGraphFunctionCloneDetectorRam(spark, "batch-platform-tmp", "batch-mode",
					40, 30, 3000, 0);
		} else {
			logger.error("Failed to find a model based on {}", choice);
			return;
		}
		final FunctionCloneDetector fmodel = model;

		LocalJobProgress.enablePrint = true;
		MathUtilities.createExpTable();
		fmodel.index(-1l, bins, new LocalJobProgress());

		double[][] matrix = new double[bins.size()][bins.size()];

		bins.stream().forEach(x -> {
			int x_ind = labelMap.get(x.binaryName);
			Counter ind = Counter.zero();
			x.functions.parallelStream().forEach(xf -> {

				ind.inc();
				List<FunctionCloneEntry> res;
				try {
					res = fmodel.detectClonesForFunc(-1l, xf, 0.5, 200, true);
				} catch (Exception e1) {
					logger.error("Failed to detect clone", e1);
					return;
				}

				System.out.println(
						"" + ind.getVal() + "/" + x.functions.size() + " " + xf.functionName + " " + res.size());

				bins.stream().forEach(y -> {

					int y_ind = labelMap.get(y.binaryName);
					OptionalDouble m = res.stream().filter(e -> e.binaryId == y.binaryId).mapToDouble(e -> e.similarity)
							.max();

					if (m.isPresent())
						matrix[x_ind][y_ind] += m.getAsDouble();
				});
			});
			for (int i = 0; i < labels.size(); ++i)
				matrix[x_ind][i] /= x.functions.size();
			matrix[x_ind][x_ind] = 1;

		});

		Result res = new Result();
		res.put(model.getClass().getSimpleName(), matrix, labels);
		ObjectMapper mapper = new ObjectMapper();
		logger.info("writing result file to {}", resPath);
		mapper.writeValue(new File(resPath), res);
	}

	public static void process(String path, String resPath, SparkInstance spark) throws Exception {

		Asm2VecNewParam param = new Asm2VecNewParam();
		param.optm_iteration = 20;
		param.vec_dim = 100;
		param.optm_parallelism = 5;

		logger.info("loading data...");
		Counter fc = Counter.zero();
		List<Binary> bins = Files.walk(Paths.get(path)).filter(Files::isRegularFile).parallel().map(p -> {
			BinarySurrogate b;
			try {
				if (p.toFile().getName().endsWith(".json")) {
					b = BinarySurrogate.load(p.toFile());
					b.processRawBinarySurrogate();
				} else {
					b = DisassemblyFactory.disassembleSingle(p.toFile());
				}

				fc.inc(b.functions.size());

				FunctionSurrogate fs = b.functions.get(0);
				fs.blocks = b.functions.stream().flatMap(f -> f.blocks.stream())
						.collect(Collectors.toCollection(ArrayList::new));
				b.functions.clear();
				b.functions.add(fs);

				Binary bin = b.toBinary();
				bin.binaryName = p.toFile().getName().split("\\.")[0] + '-' + b.md5.substring(0, 6);

				return bin;
			} catch (Exception e) {
				logger.error("Failed to load " + p, e);
				return null;
			}
		}).collect(Collectors.toList());
		logger.info("{} bins {} funcs.", bins.size(), fc.getVal());
		bins.sort((a, b) -> a.binaryName.compareTo(b.binaryName));
		List<String> labels = bins.stream().map(b -> b.binaryName).collect(Collectors.toList());
		Map<String, Integer> labelMap = IntStream.range(0, bins.size()).mapToObj(ind -> ind)
				.collect(Collectors.toMap(ind -> bins.get(ind).binaryName, ind -> ind));

		AsmObjectFactory ram = AsmObjectFactory.init(spark, "batch-mode", "kam1n0");

		Asm2VecCloneDetectorIntegration model = new Asm2VecCloneDetectorIntegration(ram, param);

		LocalJobProgress.enablePrint = true;
		MathUtilities.createExpTable();
		model.index(-1l, bins, new LocalJobProgress());

		Map<Long, double[]> embd = model.embds.row(-1l);
		Map<String, double[]> embdBin = new HashMap<>();

		double[][] matrix = new double[bins.size()][bins.size()];
		for (double[] row : matrix)
			Arrays.fill(row, 0.0);

		logger.info("Analyzing...");

		Counter c = Counter.zero();
		bins.parallelStream().forEach(x -> {
			c.inc();
			logger.info("Processing {}/{} {}", x.binaryName, c.getVal(), bins.size());
			double[] vec = new double[param.vec_dim];
			Arrays.fill(vec, 0.0);
			for (Function xf : x.functions) {
				MathUtilities.add(vec, embd.get(xf.functionId));
			}
			embdBin.put(x.binaryName, MathUtilities.normalize(vec));
		});

		c.count = 0;
		bins.parallelStream().forEach(x -> {
			c.inc();
			logger.info("Processing {}/{} {}", x.binaryName, c.getVal(), bins.size());
			bins.parallelStream().forEach(y -> {
				int x_ind = labelMap.get(x.binaryName);
				int y_ind = labelMap.get(y.binaryName);
				double score = MathUtilities.dot(embdBin.get(x.binaryName), embdBin.get(y.binaryName));
				matrix[x_ind][y_ind] = score;
				matrix[y_ind][x_ind] = score;
			});
		});

		Result res = new Result();
		res.put(model.getClass().getSimpleName(), matrix, labels);
		ObjectMapper mapper = new ObjectMapper();
		logger.info("writing result file to {}", resPath);
		mapper.writeValue(new File(resPath), res);
	}

	public static class BatchFunction extends CLIFunction {

		private ArgumentParser parser = ArgumentParser.create(Exp.class.getSimpleName());

		private Option op_dir = parser.addOption("dir", OpType.Directory, false,
				"The directory that contains a list of files to analyze.", new File("."));

		private Option op_res = parser.addOption("res", OpType.File, false,
				"The [path] and the name of the result file", new File("similarity.txt"));

		private Option op_md = parser.addSelectiveOption("md", false, "The model used in batch mode",
				Model.asmbin2vec.toString(),
				Arrays.asList(Model.values()).stream().map(m -> m.toString()).collect(Collectors.toList()));

		@Override
		public ArgumentParser getParser() {
			return this.parser;
		}

		@Override
		public String getDescription() {
			return "Batch mode";
		}

		@Override
		public String getCode() {
			return "b";
		}

		@Override
		public void process(String[] args) throws Exception {
			if (!parser.parse(args)) {
				return;
			}

			File dir = op_dir.getValue();
			File res = op_res.getValue();
			Model md = Model.valueOf(op_md.getValue());

			SparkInstance spark = SparkInstance.createLocalInstance();
			spark.init();

			
			if (md == Model.asmbin2vec)
				Batch.process(dir.getAbsolutePath(), res.getAbsolutePath(), spark);
			else
				Batch.process(dir.getAbsolutePath(), res.getAbsolutePath(), spark, md);
			System.exit(0);
		}

		@Override
		public String getCategory() {
			return "JAR Utilities";
		}

	}

	public static void main(String[] args) throws Exception {

	}

}
