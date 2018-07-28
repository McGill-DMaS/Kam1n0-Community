package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Div extends Binop {

	public Div(Graph g, String name, Tensor a, Tensor b) {
		super(g, name, a, b);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = getA().val.div(getB().val);
	}


	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA())
			return getOutputTensor().grd.div(getB().val);
		if (inputTensor == getB())
			return getA().val.mul(getOutputTensor().grd).mul(-1).mul(Transforms.sqrt(getB().val));
		return Nd4j.zerosLike(inputTensor.val);
	}

}