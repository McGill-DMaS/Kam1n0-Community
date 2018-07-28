package ca.mcgill.sis.dmas.autograd.oprs;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.api.ops.impl.transforms.IsMax;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Opr.Binop;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

/**
 * Reduce the last dim as mean
 * 
 * @author Steven
 *
 */
public class ReduceMax extends Unop {

	private int dim;
	private int[] old_shape;
	private int[] new_shape;

	public ReduceMax(Graph g, String name, Tensor a, int dim) {
		super(g, name, a);
		this.dim = dim;
	}

	@Override
	public void calOutput() {
		old_shape = getA().val.shape();
		new_shape = Arrays.copyOf(old_shape, dim + 1);
		new_shape[dim] = 1;
		for (int i = dim; i < old_shape.length; ++i)
			new_shape[dim] *= old_shape[i];
		if (new_shape.length == 1)
			new_shape = ArrayUtils.add(new_shape, 1);
		INDArray flatten = getA().val.reshape(new_shape);
		getOutputTensor().val = flatten.max(dim);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			INDArray flatten = getA().val.reshape(new_shape);
			INDArray onehot = Nd4j.getExecutioner().execAndReturn(new IsMax(flatten, dim));
			return onehot.mul(getOutputTensor().grd.reshape(ArrayUtils.add(getOutputTensor().grd.shape(), 1))
					.broadcast(onehot.shape())).reshape(old_shape);
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

	public static void main(String[] args) {

		int axis = 0;
		Graph g = Graph.create().asDefault();
		Tensor tmp = g.var_constant(Nd4j.arange(0, 3 * 4 * 5 * 6).reshape(3, 4, 5, 6));

		ReduceMax rm = new ReduceMax(g, "test", tmp, axis);
		INDArray output = rm.eval();
		rm.getOutputTensor().grd = Nd4j.onesLike(output);

		System.out.println(tmp.eval());
		System.out.println(output);
		System.out.println(rm.calDz(tmp));

	}

}