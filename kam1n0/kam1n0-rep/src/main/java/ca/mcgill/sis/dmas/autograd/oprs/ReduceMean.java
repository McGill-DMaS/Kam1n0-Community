package ca.mcgill.sis.dmas.autograd.oprs;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Opr.Binop;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

/**
 * Reduce the last dim as mean
 * 
 * @author Steven
 *
 */
public class ReduceMean extends Unop {

	private int dim;

	public ReduceMean(Graph g, String name, Tensor a, int dim) {
		super(g, name, a);
		this.dim = dim;
	}

	@Override
	public void calOutput() {
		int axis = dim == -1 ? getA().val.rank() - 1 : dim;
		getOutputTensor().val = getA().val.mean(axis);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			int axis = dim == -1 ? getA().val.rank() - 1 : dim;
			// well we can get rid of constant; but just to be more accurate.
			int[] expand_shape = Arrays.copyOf(getA().val.shape(), getA().val.rank());
			expand_shape[axis] = 1;
			INDArray grad = getOutputTensor().grd.reshape(expand_shape).broadcast(getA().val.shape());
			return grad.div(getA().val.shape()[axis]);
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

	public static void main(String[] args) {

//		INDArray tmp = Nd4j.create(new double[][] { { 1, 1, 1 }, { 2, 2, 2 }, { 3, 3, 3 } });
//		tmp.
		// ReduceMean mean = new ReduceMean(new Tensor(tmp), 0);
		// mean.calOutput();
		// mean.out.grad = Nd4j.create(new double[] { 1, 2, 3 });
		// mean.calDz();
		// System.out.println(mean.out.val);
		// System.out.println(mean.a.grad);

	}

}