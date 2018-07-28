package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.indexing.conditions.GreaterThanOrEqual;

import com.fasterxml.jackson.annotation.JsonIgnore;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Dropout extends Binop {

	private double keep_prob;
	@JsonIgnore
	private transient INDArray mask;

	public Dropout(Graph g, String name, Tensor a, Tensor keep_prob) {
		super(g, name, a, keep_prob);
	}

	@Override
	public void calOutput() {
		this.keep_prob = getB().val.getDouble(0);
		mask = Nd4j.randomFactory.getRandom().nextDouble(getA().val.shape())
				.cond(new GreaterThanOrEqual(1 - keep_prob));
		getOutputTensor().val = getA().val.mul(mask);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return getOutputTensor().grd.mul(mask);
		return Nd4j.zerosLike(inputTensor.val);
	}

	public static void main(String[] args) {
		INDArray mask = Nd4j.randomFactory.getRandom().nextDouble(new int[] { 3, 3 });
		mask = mask.cond(new GreaterThanOrEqual(0.7));
		System.out.println(mask);
	}

}