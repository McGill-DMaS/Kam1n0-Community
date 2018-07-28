package ca.mcgill.sis.dmas.nlp.model.astyle._2_cross;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

public class LinearEmbeddingMapper extends EmbeddingMapper {

	private INDArray weight;

	public void init() {
		weight = Nd4j.getRandomFactory().getNewRandomInstance(0l).nextGaussian(new int[] { in_dim, out_dim });
	}

	public INDArray transform(INDArray source) {
		return source.mmul(weight);

	}

	public Number backward(INDArray source, INDArray target, double lr) {
		INDArray dz = source.mmul(weight).sub(target).mul(2).div(out_dim);
		INDArray dw = source.transpose().mmul(dz);
		weight = weight.subi(dw.muli(lr));
		return dw.norm2Number();
	}

	public static void main(String[] args) throws Exception {
		test(LinearEmbeddingMapper.class, 400, 0.001);
	}

	@Override
	public Number cost(INDArray source, INDArray target, double lr) {
		if (lr > 0) {
			INDArray dz = source.mmul(weight).sub(target).mul(2).div(out_dim);
			INDArray dw = source.transpose().mmul(dz);
			weight = weight.subi(dw.muli(lr));
		}
		return Transforms.pow(source.mmul(weight).sub(target), 2).meanNumber();
	}

}
