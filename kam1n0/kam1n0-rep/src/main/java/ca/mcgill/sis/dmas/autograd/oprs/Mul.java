package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Mul extends Binop {

	public Mul(Graph g, String name, Tensor a, Tensor b) {
		super(g, name, a, b);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = getA().val.mul(getB().val);
	}

	// @Override
	// public void calDz() {
	// a.addGrad(b.val.mul(out.grad));
	// b.addGrad(a.val.mul(out.grad));
	// }

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return getB().val.mul(getOutputTensor().grd);
		if (inputTensor == getB())
			return getA().val.mul(getOutputTensor().grd);
		return Nd4j.zerosLike(inputTensor.val);
	}

}