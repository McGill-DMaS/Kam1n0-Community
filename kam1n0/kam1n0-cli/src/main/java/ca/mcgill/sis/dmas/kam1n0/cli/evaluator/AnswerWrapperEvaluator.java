package ca.mcgill.sis.dmas.kam1n0.cli.evaluator;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetectionResultForCLI;

public abstract class AnswerWrapperEvaluator {

	private static Logger logger = LoggerFactory.getLogger(AnswerWrapperEvaluator.class);

	public abstract List<Double> evaluate(FunctionCloneDetectionResultForCLI answers) throws Exception;

	public Double evaluateAndMerge(FunctionCloneDetectionResultForCLI answers) {
		try {
			return this.evaluate(answers).stream().mapToDouble(val -> val).average().getAsDouble();
		} catch (Exception e) {
			logger.error("Failed to evaluate " + this.metricName(), e);
			return -1d;
		}
	}

	public abstract String metricName();

	public Map<Long, String> generateIdNameMapping(FunctionCloneDetectionResultForCLI answers) {
		// List<BinarySurrogate> bins = BinarySurrogate
		// .loadAllFromFolder(Configuration.load(answers.confFile).getAsmFolderDir());
		// tmp hack after updated the format of configuration file.
		List<BinarySurrogate> bins = BinarySurrogate
				.loadAllFromFolder(new File(answers.confFile).getParentFile().getAbsolutePath() + "/asm");
		Map<Long, FunctionSurrogate> fmap = bins.stream().flatMap(bin -> bin.functions.stream())
				.collect(Collectors.toMap(func -> func.id, func -> func));

		return bins.stream().flatMap(bin -> bin.functions.stream()).collect(Collectors.toMap(func -> func.id,

				func -> func.concateName() + "[" + func.blocks.size() + "]  calls "
						+ func.call.stream().map(cl -> fmap.get(cl)).filter(cl -> cl != null).map(cl -> cl.srcName)
								.collect(Collectors.toList())

		));
	}

	public Map<Long, String> generateFuncCalls(FunctionCloneDetectionResultForCLI answers) {
		List<BinarySurrogate> bins = BinarySurrogate
				.loadAllFromFolder(Configuration.load(answers.confFile).getAsmFolderDir());
		return bins.stream().flatMap(bin -> bin.functions.stream())
				.collect(Collectors.toMap(func -> func.id,
						func -> func.blocks.stream().flatMap(blk -> blk.src.stream())
								.filter(in -> in.size() > 1 && in.get(1).equals("call")).map(in -> in.get(2))
								.collect(Collectors.joining(","))));
	}
}
