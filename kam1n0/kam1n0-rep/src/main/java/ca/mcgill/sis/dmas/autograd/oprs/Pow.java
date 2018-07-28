package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

public class Pow extends Unop {

	private double w;

	public Pow(Graph g, String name, Tensor a, double w) {
		super(g, name, a);
		this.w = w;
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = Transforms.pow(getA().val, w);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return getOutputTensor().grd.mul(w).mul(Transforms.pow(getA().val, w - 1));
		return Nd4j.zerosLike(inputTensor.val);
	}

}