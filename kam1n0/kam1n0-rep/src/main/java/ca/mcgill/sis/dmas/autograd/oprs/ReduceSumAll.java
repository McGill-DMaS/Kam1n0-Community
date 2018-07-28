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
public class ReduceSumAll extends Unop {

	public ReduceSumAll(Graph g, String name, Tensor a) {
		super(g, name, a);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = Nd4j.scalar(getA().val.sumNumber());
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			INDArray grad = getOutputTensor().grd;
			return grad;
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

	public static void main(String[] args) {

		// INDArray tmp = Nd4j.create(new double[][] { { 1, 1, 1 }, { 2, 2, 2 }, { 3, 3,
		// 3 } });
		// ReduceSum mean = new ReduceSum(new Tensor(tmp), 0);
		// mean.calOutput();
		// mean.out.grad = Nd4j.create(new double[] { 1, 2, 3 });
		// mean.calDz();
		// System.out.println(mean.out.val);
		// System.out.println(mean.a.grad);

	}

}