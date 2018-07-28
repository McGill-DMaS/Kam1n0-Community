package ca.mcgill.sis.dmas.autograd.oprs;

import java.util.Arrays;

import org.apache.commons.lang3.ArrayUtils;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

public class Flatten extends Unop {

	private int dim;
	private int[] new_shape;
	private int[] old_shape;

	public Flatten(Graph g, String name, Tensor a, int dim) {
		super(g, name, a);
		this.dim = dim;
	}

	@Override
	public void calOutput() {
		int axis = dim == -1 ? getA().val.rank() - 1 : dim;
		old_shape = getA().val.shape();
		new_shape = Arrays.copyOf(old_shape, axis + 1);
		new_shape[axis] = 1;
		for (int i = axis; i < old_shape.length; ++i)
			new_shape[axis] *= old_shape[i];
		if (new_shape.length == 1)
			new_shape = ArrayUtils.add(new_shape, 1);
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