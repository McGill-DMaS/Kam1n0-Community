package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class Reshape extends Unop {

	private int[] shape;
	private int[] old_shape;

	public Reshape(Graph g, String name, Tensor a, int... shape) {
		super(g, name, a);
		this.shape = shape;
	}

	@Override
	public void calOutput() {
		old_shape = getA().val.shape();
		getA().val.reshape(shape);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			return getOutputTensor().grd.reshape(old_shape);
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

}
