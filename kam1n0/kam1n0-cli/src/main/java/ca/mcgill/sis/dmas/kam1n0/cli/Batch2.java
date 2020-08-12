package ca.mcgill.sis.dmas.kam1n0.cli;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.StreamSupport;

import org.apache.commons.lang3.NotImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.SocketUtils;

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
import ca.mcgill.sis.dmas.kam1n0.app.clone.BinaryAnalysisProcedureCompositionAnalysis;
import ca.mcgill.sis.dmas.kam1n0.app.clone.CloneSearchResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.FunctionCloneDetectorForWeb;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDetectionResultForWeb;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileInfo;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileServingUtils;
import ca.mcgill.sis.dmas.kam1n0.cli.Batch.Result;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.Exp;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectorForCLI;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.DetectorsKam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.LogicGraphFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep.Asm2VecCloneDetectorIntegration;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;
import scala.Tuple2;
import scala.Tuple3;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.graph.Kam1n0SymbolicModule;

public class Batch2 {
	private static Logger logger = LoggerFactory.getLogger(Batch2.class);

	// Any simple value would do, as long as this can't be a valid filename
	private static String filterValueForIndexingOnly = "*";

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

	public static class Dataset implements Iterable<BinaryMultiParts> {

		private static Binary loadAssembly(File p, boolean mergeFunctions) {
			BinarySurrogate b;
			try {
				if (p.getName().endsWith(".json")) {
					b = BinarySurrogate.load(p);
					b.processRawBinarySurrogate();
				} else {
					b = DisassemblyFactory.disassembleSingle(p);
					if (mergeFunctions) {
						FunctionSurrogate fs = b.functions.get(0);
						fs.blocks = b.functions.stream().flatMap(f -> f.blocks.stream())
								.collect(Collectors.toCollection(ArrayList::new));
						b.functions.clear();
						b.functions.add(fs);
					}
				}
				Binary bin = b.toBinary();
				bin.binaryName = p.getName().split("\\.")[0] + '-' + b.md5.substring(0, 8);

				return bin;
			} catch (Exception e) {
				logger.error("Failed to load " + p, e);
				return null;
			}
		}

		public List<Tuple3<Long, String, File>> vals;
		public Architecture arch = null;
		public boolean mergeFunctions = false;
		public List<String> labels;
		public Map<String, Integer> labelMap;
		private Map<Long, Integer> functionCountByBinaryId;
		private Predicate<? super Tuple3<Long, String, File>> processingFileFilter = (x -> true);

		public Dataset(String path, boolean mergeFunctions) throws Exception {
			this.mergeFunctions = mergeFunctions;
			this.functionCountByBinaryId = new HashMap<>();
			logger.info("creating a mapping between binary names and the data...");
			// ID, name, & File
			vals = new ArrayList<>(Files.walk(Paths.get(path)).filter(Files::isRegularFile).parallel().map(p -> {
				Binary b = loadAssembly(p.toFile(), this.mergeFunctions);
				if (b == null)
					return null;
				else {
					if (this.arch == null)
						this.arch = b.architecture;
					functionCountByBinaryId.putIfAbsent(b.binaryId, b.functions.size());
					return new Tuple3<>(b.binaryId, b.binaryName, p.toFile());
				}
				// filtering and de-duplication:
			}).filter(t3 -> t3 != null).collect(Collectors.toMap(t3 -> t3._1(), t3 -> t3, (t3n, t3o) -> t3n)).values());

			// sorted based on names
			vals.sort((a, b) -> a._2().compareTo(b._2()));

			this.labels = vals.stream().map(t3 -> t3._2()).collect(Collectors.toList());
			this.labelMap = IntStream.range(0, this.labels.size()).mapToObj(ind -> ind)
					.collect(Collectors.toMap(ind -> this.labels.get(ind), ind -> ind));
		}

		// Rationale: this.iterator().filter(...) is very costly, since it will call loadAssembly for each files BEFORE
		// 			  passing them on to the filter. Instead, this processing filter will occur before loadAssembly.
		public void setProcessingFilter(Predicate<? super Tuple3<Long, String, File>> predicate) {
			processingFileFilter = predicate;
		}

		@Override
		public Iterator<BinaryMultiParts> iterator() {
			return vals.stream().
					filter(processingFileFilter).
					map(t3 -> loadAssembly(t3._3(), this.mergeFunctions).converToMultiPart()).
					iterator();
		}

		public int size() {
			return this.vals.size();
		}

		public int totalFunctions(){
			return vals.stream().mapToInt(t3 -> functionCountByBinaryId.getOrDefault(t3._1(), 0)).sum();
		}

	}

	public static void process(String path, String resPath, String filterFilename, SparkInstance spark, Model choice,
			CassandraInstance cassandra) throws Exception {

		Dataset ds = new Dataset(path, false);
		logger.info("{} bins. {} functions.", ds.size(), ds.totalFunctions());

		if (ds.size() < 1)
			return;

		NormalizationSetting setting = NormalizationSetting.New();
		setting.setNormalizationLevel(NormalizationLevel.NORM_LENGTH);
		AsmObjectFactory factory = AsmObjectFactory.init(spark, cassandra, "batch2t", "trial2");
		AsmProcessor processor = new AsmProcessor(ds.arch.type.retrieveDefinition(), setting);

		FunctionCloneDetector model = null;
		if (choice == Model.asm2vec || choice == Model.asmbin2vec) {
			Asm2VecNewParam param = new Asm2VecNewParam();
			param.optm_iteration = 5;
			param.vec_dim = 50;
			param.optm_parallelism = 5;
			model = new Asm2VecCloneDetectorIntegration(factory, param);
		} else if (choice == Model.asmclone) {
			model = DetectorsKam.getLshAdaptiveSubGraphFunctionCloneDetectorCassandra(spark, cassandra, factory,
					processor, 16, 1024, 1, 30, 1);
		} else if (choice == Model.sym1n0) {
			Kam1n0SymbolicModule.setup();
			LogicGraphFactory logicFactory = LogicGraphFactory.init(spark, cassandra, "batch2t", "sym1n0");
			model = DetectorsKam.getSymbolicSubGraphFunctionCloneDetectorCassandra(factory, logicFactory, spark,
					cassandra, 40, 30, 3000, 0);
		} else {
			logger.error("Failed to find a model based on {}", choice);
			return;
		}
		final FunctionCloneDetector fmodel = model;
		fmodel.init();

		LocalJobProgress.enablePrint = true;
		MathUtilities.createExpTable();
		if (filterFilename.isEmpty() || filterFilename.equals(filterValueForIndexingOnly)) {
			fmodel.index(-1l, ds, new LocalJobProgress());
		}

		double[][] matrix = new double[ds.size()][ds.size()];
		for (double[] row : matrix)
			Arrays.fill(row, 0.0);

		Result res = new Result();
		if (choice.equals(Model.asmbin2vec)) {
			Asm2VecCloneDetectorIntegration model2 = (Asm2VecCloneDetectorIntegration) model;
			Map<Long, double[]> embd = model2.embds.row(-1l);
			Map<String, double[]> embdBin = new HashMap<>();
			logger.info("Analyzing...");

			Counter c = Counter.zero();
			ds.vals.parallelStream().forEach(x -> {
				c.inc();
				logger.info("Processing {}/{} {}", x._2(), c.getVal(), ds.size());
				double[] vec = new double[model2.param.vec_dim];
				Arrays.fill(vec, 0.0);
				for (Function xf : Dataset.loadAssembly(x._3(), true)) {
					MathUtilities.add(vec, embd.get(xf.functionId));
				}
				embdBin.put(x._2(), MathUtilities.normalize(vec));
			});

			c.count = 0;
			ds.vals.parallelStream().forEach(x -> {
				c.inc();
				logger.info("Processing {}/{} {}", x._2(), c.getVal(), ds.size());
				ds.vals.parallelStream().forEach(y -> {
					int x_ind = ds.labelMap.get(x._2());
					int y_ind = ds.labelMap.get(y._2());
					double score = MathUtilities.dot(embdBin.get(x._2()), embdBin.get(y._2()));
					matrix[x_ind][y_ind] = score;
					matrix[y_ind][x_ind] = score;
				});
			});

			res.put(model.getClass().getSimpleName(), matrix, ds.labels);
 		} else if (!filterFilename.equals(filterValueForIndexingOnly))  {
			Counter c = Counter.zero();
			Counter tf = Counter.zero();

			if (!filterFilename.isEmpty()) {
				ds.setProcessingFilter(m -> m._3().getName().equals(filterFilename));
			}

			StreamSupport.stream(ds.spliterator(), false).forEach(m -> m.forEach(x -> {
				c.inc();
				int x_ind = ds.labelMap.get(x.binaryName);
				Counter ind = Counter.zero();
				x.functions.parallelStream().forEach(xf -> {

					ind.inc();
					tf.inc();
					List<FunctionCloneEntry> fres;
					try {
						fres = fmodel.detectClonesForFunc(-1l, xf, 0.5, 200, true);
					} catch (Exception e1) {
						logger.error("Failed to detect clone", e1);
						return;
					}

					System.out.println("" + ind.getVal() + "/" + x.functions.size() + " " + c.getVal() + "/" + ds.size()
							+ "/" + tf.getVal() + " " + xf.functionName + " " + fres.size());

					ds.vals.stream().forEach(t3 -> {

						long y_id = t3._1();
						String y_name = t3._2();

						int y_ind = ds.labelMap.get(y_name);
						OptionalDouble val = fres.stream().filter(e -> e.binaryId == y_id)
								.mapToDouble(e -> e.similarity).max();

						if (val.isPresent())
							matrix[x_ind][y_ind] += val.getAsDouble();
					});
				});
				for (int i = 0; i < ds.labels.size(); ++i)
					matrix[x_ind][i] /= x.functions.size();
				matrix[x_ind][x_ind] = 1;

			}));

			res.put(model.getClass().getSimpleName(), matrix, ds.labels);

		}
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

		private Option filterOption = parser.addOption("filter", OpType.String, false,
				"asmclone only, 2-step process: // none: normal batch processing // " +
						filterValueForIndexingOnly + ": create permanent local DB only // " +
						"filename: compare only that file against the previously made DB", "");

		private Option op_md = parser.addSelectiveOption("md", false, "The model used in batch mode",
				Model.asmbin2vec.toString(),
				Arrays.asList(Model.values()).stream().map(m -> m.toString()).collect(Collectors.toList()));

		@Override
		public ArgumentParser getParser() {
			return this.parser;
		}

		@Override
		public String getDescription() {
			return "Batch mode 2";
		}

		@Override
		public String getCode() {
			return "b2";
		}

		@Override
		public void process(String[] args) {
			if (!parser.parse(args)) {
				System.exit(0);
			}

			try {

				File dir = op_dir.getValue();
				File res = op_res.getValue();
				Model md = Model.valueOf(op_md.getValue());
				String filterFilename = filterOption.getValue();

				if ( !md.equals(Model.asmclone) && !filterFilename.isEmpty() ) {
					logger.warn("'filter' option is for 'asmclone' only. Current value will be ignored.");
					filterFilename = "";
				}

				CassandraInstance cassandra = CassandraInstance.createEmbeddedInstance("test-batch-mode", filterFilename.isEmpty(), false);
				cassandra.init();
				SparkInstance spark = SparkInstance.createLocalInstance(cassandra.getSparkConfiguration());
				spark.init();
				cassandra.setSparkInstance(spark);
				Batch2.process(dir.getAbsolutePath(), res.getAbsolutePath(), filterFilename, spark, md, cassandra);
			} catch (Exception e) {
				logger.info("Failed to process " + Arrays.toString(args), e);
			}
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
