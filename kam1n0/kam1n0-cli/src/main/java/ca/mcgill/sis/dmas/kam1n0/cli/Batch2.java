package ca.mcgill.sis.dmas.kam1n0.cli;

import java.io.File;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.env.*;
import org.apache.cassandra.db.commitlog.CommitLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.Exp;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.DetectorsKam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.LogicGraphFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep.Asm2VecCloneDetectorIntegration;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.graph.Kam1n0SymbolicModule;

public class Batch2 {
	private static final Logger logger = LoggerFactory.getLogger(Batch2.class);

	private static final int MAX_FIND_CLONE_RETRIES_ON_ERROR = 10;

	private static class FunctionCloneSearchResult {
        public List<FunctionCloneEntry> foundClones;

		// wall-clock time (not CPU time), and only for the last (successful) attempt if it was retried
        public long processTimeMs;
    }

	public static class HeatMapData {
		public double[][] similarity;
		public List<String> labels;
	}

	public static class Result {
		public Map<String, HeatMapData> contents = new HashMap<>();
		public Map<String, String> templates = new HashMap<>();

		public void put(String key, double[][] data, List<String> labels) {
			HeatMapData hm = new HeatMapData();
			hm.similarity = data;
			hm.labels = labels;
			contents.put(key, hm);
			templates.put(key, "HeatMap");
		}
	}

	public enum Model {
		asm2vec, asmbin2vec, sym1n0, asmclone, cassandra
	}

	private static FunctionCloneDetector instantiateModel(Model choice, SparkInstance spark, CassandraInstance cassandra,
												   Architecture architecture) throws Exception {
		NormalizationSetting setting = NormalizationSetting.New();
		setting.setNormalizationLevel(NormalizationLevel.NORM_LENGTH);
		AsmObjectFactory factory = AsmObjectFactory.init(spark, cassandra, "batch2t", "trial2");
		AsmProcessor processor = new AsmProcessor(architecture.type.retrieveDefinition(), setting);

		FunctionCloneDetector model;
		if (choice == Model.asm2vec || choice == Model.asmbin2vec) {
			Asm2VecNewParam param = new Asm2VecNewParam();
			param.optm_iteration = 5;
			param.vec_dim = 50;
			param.optm_parallelism = 5;
			// statefull model: indexation result is stored within the model itself
			model = new Asm2VecCloneDetectorIntegration(factory, param);
		} else if (choice == Model.asmclone) {
			// stateless model instance: indexation result is stored in Cassandra DB
			model = DetectorsKam.getLshAdaptiveSubGraphFunctionCloneDetectorCassandra(spark, cassandra, factory,
					processor, 16, 1024, 1, 30, 1, true);
		} else if (choice == Model.sym1n0) {
			// stateless model instance: indexation result is stored in Cassandra DB
			Kam1n0SymbolicModule.setup();
			LogicGraphFactory logicFactory = LogicGraphFactory.init(spark, cassandra, "batch2t", "sym1n0");
			model = DetectorsKam.getSymbolicSubGraphFunctionCloneDetectorCassandra(factory, logicFactory, spark,
					cassandra, 40, 30, 3000, 0);
		} else {
			throw new IllegalArgumentException(MessageFormat.format("Failed to find a model based on {}", choice));
		}
		model.init();
		return model;
	}

	/**
	 * This is a workaround for the Spark/Cassandra stack that seems to have random connection failures once
	 * every few hours (occurs on less than 0.1% of searches). No cause was ever identified yet. Retrying the clone
	 * search normally just works.
	 *
	 * @param functionModel function clone search model
	 * @param targetFunction function to search clones for
	 * @return found clones, or null if all retry attempts failed.
	 */
	private static FunctionCloneSearchResult detectClonesWithRetries(
			FunctionCloneDetector functionModel, Function targetFunction) throws Exception {

		long attemptStartTime = 0;
		int attempt = 0;
		List<FunctionCloneEntry> foundClones = null;

		while (foundClones == null && attempt < MAX_FIND_CLONE_RETRIES_ON_ERROR) {
			attemptStartTime = new Date().getTime();
			attempt++;

			try {
				foundClones = functionModel.detectClonesForFunc(-1L, targetFunction, 0.5, 200, true);
			} catch (Exception e) {
				if (attempt < MAX_FIND_CLONE_RETRIES_ON_ERROR) {
					logger.warn(String.format("Failed to detect clone for %s, on attempt %d/%d. Will retry.",
							targetFunction.functionName, attempt, MAX_FIND_CLONE_RETRIES_ON_ERROR), e);
				} else {
					throw e;
				}
			}
		}

		FunctionCloneSearchResult result = new FunctionCloneSearchResult();
		result.foundClones = foundClones;
		result.processTimeMs = new Date().getTime() - attemptStartTime;
		return result;
	}

	private static void processFilesWithAsmBin2Vec(FunctionCloneDetector model, BatchState batch) {
		BatchDataset dataset = batch.getDataset();
		Asm2VecCloneDetectorIntegration model2 = (Asm2VecCloneDetectorIntegration) model;
		Map<Long, double[]> embd = model2.embds.row(-1L);
		Map<String, double[]> embdBin = new HashMap<>();
		double[] matrixRow = new double[dataset.size()];

		logger.info("Analyzing...");

		Counter c = Counter.zero();
		dataset.getEntries().parallelStream().forEach(x -> {
			c.inc();
			logger.info("Processing {}/{} {}", x.binaryName, c.getVal(), dataset.size());
			double[] vec = new double[model2.param.vec_dim];
			Arrays.fill(vec, 0.0);
			for (Function xf : dataset.getBinary(x.matrixIndex, true)) {
				MathUtilities.add(vec, embd.get(xf.functionId));
			}
			embdBin.put(x.binaryName, MathUtilities.normalize(vec));
		});

		c.count = 0;
		dataset.getEntries().parallelStream().forEach(x -> {
			c.inc();
			logger.info("Processing {}/{} {}", x.binaryName, c.getVal(), dataset.size());
			dataset.getEntries().parallelStream().forEach(y -> {
				double score = MathUtilities.dot(embdBin.get(x.binaryName), embdBin.get(y.binaryName));
				matrixRow[y.matrixIndex] = score;
			});
			try {
				batch.notifyFileProcessed(x.matrixIndex, matrixRow);
			} catch( Exception e ) {
				throw new RuntimeException(e);
			}
		});
	}

	private static void processFilesGeneral(FunctionCloneDetector model, BatchState batch, String resPath) {
		BatchDataset dataset = batch.getDataset();

		List<Integer> doneSoFar = batch.getAlreadyDoneFiles();
		Counter fileCounter = Counter.zero();
		fileCounter.count = doneSoFar.size();
		AtomicInteger totalFunctionCount = new AtomicInteger(
				doneSoFar.stream().mapToInt(index -> dataset.getEntries().get(index).functionCount).sum() );

		batch.getFilesToProcess().forEach(targetIndex -> {
			fileCounter.inc();
			AtomicInteger functionCount = new AtomicInteger(0);

			double[] similarities = new double[dataset.size()];
			Arrays.fill(similarities, 0.0);

			Binary targetBinary = dataset.getBinary(targetIndex);
			targetBinary.functions.parallelStream().forEach(targetFunction -> {

				FunctionCloneSearchResult searchResult;
				try {
					searchResult = detectClonesWithRetries(model, targetFunction);
				} catch (Exception e1) {
					logger.error(String.format("Failed to detect clone for %s, after %d attempt(s). Similarity result will be wrong for this file.",
							targetFunction.functionName, MAX_FIND_CLONE_RETRIES_ON_ERROR), e1);
					return;
				}

				int completedFunctionCount = functionCount.incrementAndGet();
				int totalCompletedFunctions = totalFunctionCount.incrementAndGet();
				logger.info("File:#{} ({}/{}) Function:{}/{}/{} {} clones:{} wallClockProcessTime:{}",
						targetIndex, fileCounter.getVal(), dataset.size(),
						completedFunctionCount, targetBinary.functions.size(), totalCompletedFunctions,
						targetFunction.functionName, searchResult.foundClones.size(), searchResult.processTimeMs);

				dataset.getEntries().forEach(sourceEntry -> {
					OptionalDouble val = searchResult.foundClones.stream().filter(e -> e.binaryId == sourceEntry.binaryId)
							.mapToDouble(e -> e.similarity).max();
					if (val.isPresent()) {
						synchronized (similarities) {
							similarities[sourceEntry.matrixIndex] += val.getAsDouble();
						}
					}
				});
			});

			for (int i = 0; i < similarities.length; ++i)
				similarities[i] /= targetBinary.functions.size();
			similarities[targetIndex] = 1.0;

			try {
				batch.notifyFileProcessed(targetIndex, similarities);
				writeSimilarityMatrix(resPath, batch.getSimilarityMatrix(), dataset, model.getClass().getSimpleName(), false);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}


	private static void writeSimilarityMatrix(String resultPath, double[][] matrix, BatchDataset dataset,
                                              String modelName, boolean finalResult) throws Exception {
		Result result = new Result();
		result.put(modelName, matrix, dataset.getEntries().stream().map(entry -> entry.binaryName).collect(Collectors.toList()));

		logger.info("Writing similarity matrix {}to {}", finalResult ? "" : "so far ", resultPath);
		ObjectMapper mapper = new ObjectMapper();
		mapper.writerWithDefaultPrettyPrinter().writeValue(new File(resultPath), result);
	}

	public static void process(String path, String resPath, boolean allowResume, SparkInstance spark, Model choice,
			CassandraInstance cassandra) throws Exception {

		BatchState batch = BatchState.createOrResume(allowResume);

		// Create/reuse dataset
		BatchDataset dataset;
		if (batch.getLastCompletedStage().compareTo(BatchState.Stage.CREATE_DATASET) < 0) {
			dataset = new BatchDataset(Paths.get(path), false);
			batch.notifyDatasetCreated(dataset);
		} else {
			dataset = batch.getDataset();
		}
		if (dataset.size() == 0) {
			logger.warn("Found no file to process. Aborting batch.");
			batch.notifyCompleted();
			return;
		}

		// Instantiate model
		// Note: 'resumable' models are stateless regarding indexing/processing stages below and keep all state/data
		//       in an external database.
		FunctionCloneDetector model = instantiateModel(choice, spark, cassandra, dataset.getArchitecture());
		LocalJobProgress.enablePrint = true;
		MathUtilities.createExpTable();

		// Index files
		if (batch.getLastCompletedStage().compareTo(BatchState.Stage.INDEX_FILES) < 0) {
			model.index(-1L, dataset.getAllBinariesAsMultiParts(), new LocalJobProgress());
			logger.info("Indexing completed.");
			batch.notifyIndexingDone();
		}

		// forceRecycleAllSegments() flushes data to SStables and removes unneeded commit logs. This makes read
		// operations a bit faster afterwards (all data in SStable, not scattered in commit logs) and only makes sense
		// at this point since we're done updating tables and will only query them for the rest of the batch process.
		CommitLog.instance.forceRecycleAllSegments();
		// Flushing also triggers SStable compaction if needed, then we wait for it to complete
		cassandra.waitForCompactionTasksCompletion();

		// Process files
		if (choice.equals(Model.asmbin2vec)) {
			processFilesWithAsmBin2Vec(model, batch);
 		} else {
			processFilesGeneral(model, batch, resPath);
		}

		// Export result
        writeSimilarityMatrix(resPath, batch.getSimilarityMatrix(), dataset, model.getClass().getSimpleName(), true);
		batch.notifyCompleted();
	}

	public static class BatchFunction extends CLIFunction {

		private final ArgumentParser parser = ArgumentParser.create(Exp.class.getSimpleName());

		private final Option op_dir = parser.addOption("dir", OpType.Directory, false,
				"The directory that contains a list of files to analyze.", new File("."));

		private final Option op_res = parser.addOption("res", OpType.File, false,
				"The [path] and the name of the result file", new File("similarity.txt"));

		private final Option resumeOption = parser.addOption("resume", OpType.Boolean, false,
				"asmclone/sym1n0 only: create/resume resumable batch process, creating/reusing DB under working folder", false);

		private final Option op_md = parser.addSelectiveOption("md", false, "The model used in batch mode",
				Model.asmbin2vec.toString(),
				Arrays.stream(Model.values()).map(Enum::toString).collect(Collectors.toList()));

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

				boolean resuming = resumeOption.getValue();
				if ( resuming && !md.equals(Model.asmclone) && !md.equals(Model.sym1n0) ) {
					logger.warn("'resume' option is for 'asmclone' and 'sym1n0' only. Will be ignored.");
					resuming = false;
				}

				CassandraInstance cassandra = CassandraInstance.createEmbeddedInstance("test-batch-mode", !resuming, false);
				cassandra.init();

				if (!md.equals(Model.cassandra)) {
					SparkInstance spark = SparkInstance.createLocalInstance(cassandra.getSparkConfiguration());
					spark.init();
					cassandra.setSparkInstance(spark);
					Batch2.process(dir.getAbsolutePath(), res.getAbsolutePath(), resuming, spark, md, cassandra);
				} else {
					logger.info("No processing. Only running local cassandra server from database in current working directory.");

					System.out.println("You may now use external tools on Cassandra database.");
					System.out.println("Press Enter to terminate server");
					Scanner scanner = new Scanner(System.in);
					scanner.nextLine();

					logger.info("Termination requested.");
				}

				cassandra.close();

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

	public static void main(String[] args) {
	}

}
