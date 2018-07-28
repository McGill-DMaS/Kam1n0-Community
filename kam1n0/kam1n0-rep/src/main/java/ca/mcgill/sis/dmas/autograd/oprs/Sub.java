package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Sub extends Binop {

	public Sub(Graph g, String name, Tensor a, Tensor b) {
		super(g, name, a, b);
	}

	@Override
	public void calOutput() {
		if (getB().val.shape()[0] == 1)
			getOutputTensor().val = getA().val.subRowVector(getB().val);
		else
			getOutputTensor().val = getA().val.sub(getB().val);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return getOutputTensor().grd;
		if (inputTensor == getB())
			return getOutputTensor().grd.mul(-1);
		return Nd4j.zerosLike(inputTensor.val);
	}

}