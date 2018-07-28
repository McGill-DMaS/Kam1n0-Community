package ca.mcgill.sis.dmas.nlp.model.astyle._2_cross;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;

public abstract class EmbeddingMapper {

	private static Logger logger = LoggerFactory.getLogger(EmbeddingMapper.class);

	int in_dim;
	int out_dim;

	public EmbeddingMapper() {

	}

	private double[][] convert(List<String> keys, Map<String, double[]> embd) {
		double[][] a = new double[keys.size()][];
		for (int i = 0; i < keys.size(); ++i)
			a[i] = embd.get(keys.get(i));
		return a;
	}

	public void train(Map<String, double[]> embd1, Map<String, double[]> embd2, int epoch, double lr) {

		HashSet<String> alignment = new HashSet<>(embd1.keySet());
		alignment.retainAll(embd2.keySet());
		ArrayList<String> alignment_ls = new ArrayList<>(alignment);
		Collections.shuffle(alignment_ls, new Random(0));

		int split = (int) (alignment_ls.size() * 0.8);
		List<String> train_keys = alignment_ls.subList(0, split);
		List<String> testn_keys = alignment_ls.subList(split, alignment.size());

		in_dim = embd1.values().stream().findAny().get().length;
		out_dim = embd2.values().stream().findAny().get().length;

		this.init();

		INDArray src_train = Nd4j.create(this.convert(train_keys, embd1));
		INDArray tar_train = Nd4j.create(this.convert(train_keys, embd2));
		INDArray src_testn = Nd4j.create(this.convert(testn_keys, embd1));
		INDArray tar_testn = Nd4j.create(this.convert(testn_keys, embd2));

		logger.info("{} training alignments and {} testing alignments {} -> {}", train_keys.size(), testn_keys.size(),
				in_dim, out_dim);

		for (int i = 0; i < epoch; ++i) {
			Number cost = cost(src_train, tar_train, lr);
			Number cost_test = cost(src_testn, tar_testn, -1);
			System.out.println("epoch " + i + " cost " + cost + " cost test " + cost_test);
		}
		INDArray sampled = transform(src_testn);
		for (int i = 0; i < 10; i++) {
			System.out.println(sampled.getRow(i));
			System.out.println(tar_testn.getRow(i));
			System.out.println();
		}
	}

	public abstract INDArray transform(INDArray src_testn);

	public abstract Number cost(INDArray src_train, INDArray tar_train, double lr);

	public abstract void init();

	public static void test(Class<? extends EmbeddingMapper> cls, int epoch, double lr) throws Exception {
		Environment.init();

		Random rand = new Random(0l);
		int batch = 10000;
		int dim = 100;

		double[][] a = new double[batch][dim];
		for (int i = 0; i < batch; ++i)
			for (int j = 0; j < dim; ++j)
				a[i][j] = rand.nextFloat() * 2 - 1;
		double[][] b = new double[batch][dim];
		for (int i = 0; i < batch; ++i)
			for (int j = 0; j < dim; ++j)
				b[i][j] = a[i][j] * (j % 9);

		HashMap<String, double[]> src = new HashMap<>();
		HashMap<String, double[]> tar = new HashMap<>();
		for (int i = 0; i < batch; ++i) {
			src.put(Integer.toString(i), a[i]);
			tar.put(Integer.toString(i), b[i]);
		}

		EmbeddingMapper mapper = cls.newInstance();
		mapper.train(src, tar, epoch, lr);
	}

}
