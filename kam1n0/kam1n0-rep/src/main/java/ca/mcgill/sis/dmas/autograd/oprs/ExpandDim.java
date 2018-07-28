package ca.mcgill.sis.dmas.autograd.oprs;

import org.apache.commons.lang3.ArrayUtils;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

public class ExpandDim extends Unop {

	private int dim;
	private int[] new_shape;
	private int[] old_shape;

	public ExpandDim(Graph g, String name, Tensor a, int dim) {
		super(g, name, a);
		this.dim = dim;
	}

	@Override
	public void calOutput() {
		old_shape = getA().val.shape();
		new_shape = ArrayUtils.add(old_shape, dim, 1);
		getOutputTensor().val = getA().val.reshape(new_shape);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			return getOutputTensor().grd.reshape(old_shape);
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

}