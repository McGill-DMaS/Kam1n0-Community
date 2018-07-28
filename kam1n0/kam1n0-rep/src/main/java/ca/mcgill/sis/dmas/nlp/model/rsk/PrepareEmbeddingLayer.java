package ca.mcgill.sis.dmas.nlp.model.rsk;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.FuncTokenized;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;
import ca.mcgill.sis.dmas.nlp.model.rsk.MalStruct.Sample;

public class PrepareEmbeddingLayer {
	private static Logger logger = LoggerFactory.getLogger(PrepareEmbeddingLayer.class);

	public static void main(String[] args) throws Exception {
		Environment.init();
		generate(args[0]);
	}

	@SafeVarargs
	public static <T> Predicate<T> or(Predicate<T>... conds) {
		return val -> {
			for (Predicate<T> cond : conds)
				if (cond.test(val))
					return true;
			return false;
		};
	}

	public static float[] convertToFloat(double[] vec) {
		float[] nvec = new float[vec.length];
		for (int i = 0; i < vec.length; ++i) {
			float fval = (float) vec[i];
			nvec[i] = fval;
		}
		return nvec;
	}

	public static void generate(String folder) throws Exception {

		String output_folder = folder;
		if (!new File(output_folder).exists())
			new File(output_folder).mkdirs();

		if (MathUtilities.expTable == null)
			MathUtilities.createExpTable();

		Asm2VecNewParam param = new Asm2VecNewParam();
		param.vec_dim = 50;
		param.optm_iteration = 30;
		param.optm_window = 1;
		param.optm_negSample = 20;
		param.optm_initAlpha = 0.007;
		param.optm_subsampling = 1e-4d;
		param.optm_parallelism = 36;
		param.min_freq = 1;

		logger.info("loading from {}", output_folder);
		Iterable<Sample> sams = MalStruct.loadAsIte(output_folder);
		Iterable<FuncTokenized> funcs = Iterables.transform(sams, x -> x.convert());

		LearnerAsm2VecEmbdOnly model = new LearnerAsm2VecEmbdOnly(param);
		model.debug = true;
		model.train(funcs);
		// model.produce().save(new File(tns_folder + "\\wor2vec.bin"));
		logger.info("checking unique imports.");
		Set<String> fns = StreamSupport.stream(sams.spliterator(), true).filter(sam -> sam.impF != null)
				.flatMap(sam -> sam.impF.stream()).map(String::toLowerCase).collect(Collectors.toSet());

		// writing embeddings
		{
			System.out.println(Arrays.toString(model.vocabL.get(0).neuIn));
			try (DataOutputStream stream = new DataOutputStream(
					new FileOutputStream(new File(output_folder + "/embd.bin")));) {
				model.vocabL.stream().forEachOrdered(node -> {
					for (float val : convertToFloat(node.neuIn))
						try {
							stream.writeFloat(val);
						} catch (IOException e) {
							logger.error("Failed to write float");
						}
				});
			}
			LineSequenceWriter writer = Lines.getLineWriter(output_folder + "/embd.tsv", false);
			writer.writeLine("Word" + "\t" + "Frequency" + "\t" + "Type" + "\t" + "Original");
			model.vocabL.stream().forEachOrdered(node -> {
				try {
					String grp = MalStruct.get_grp(node.token, fns);
					writer.writeLine(grp + "-" + node.token + "\t" + node.freq + "\t" + grp + "\t" + node.token);
				} catch (Exception e) {
					logger.error("Failed to write meta");
				}
			});
			writer.close();
		}

	}

}
