package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

public class Sigmoid extends Unop {

	public Sigmoid(Graph g, String name, Tensor a) {
		super(g, name, a);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = Transforms.sigmoid(getA().val);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return Transforms.sigmoidDerivative(getA().val).mul(getOutputTensor().grd);
		return Nd4j.zerosLike(inputTensor.val);
	}

}
