package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

public class HardTanh extends Unop {

	public HardTanh(Graph g, String name, Tensor a) {
		super(g, name, a);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = Transforms.hardTanh(getA().val);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return Transforms.hardTanhDerivative(inputTensor.val).mul(getOutputTensor().grd);
		return Nd4j.zerosLike(inputTensor.val);
	}

}
