package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Matmul extends Binop {

	public Matmul(Graph g, String name, Tensor a, Tensor b) {
		super(g, name, a, b);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = getA().val.mmul(getB().val);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getB())
			return getA().val.transpose().mmul(getOutputTensor().grd);
		if (inputTensor == getA()) {
			return getOutputTensor().grd.mmul(getB().val.transpose());
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

	// @Override
	// public INDArray prop(INDArray dZ, double lr) {
	// INDArray dW = X.transpose().mmul(dZ);
	// W.subi(dW.muli(lr));
	// INDArray dX = dZ.mmul(W.transpose());
	// return dX;
	// }

}