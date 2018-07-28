package ca.mcgill.sis.dmas.autograd.oprs;

import ca.mcgill.sis.dmas.autograd.Tensor;

import java.util.Arrays;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Add extends Binop {

	public Add(Graph g, String name, Tensor a, Tensor b) {
		super(g, name, a, b);
	}

	@Override
	public void calOutput() {
		Tensor at = getA();
		Tensor bt = getB();
		if (Arrays.equals(at.val.shape(), bt.val.shape()))
			getOutputTensor().val = at.val.add(bt.val);
		else
			getOutputTensor().val = at.val.addRowVector(bt.val);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA() || inputTensor == getB())
			if (Arrays.equals(getOutputTensor().val.shape(), inputTensor.val.shape()))
				return getOutputTensor().grd;
			else
				return getOutputTensor().grd.mean(0);
		return Nd4j.zerosLike(inputTensor.val);
	}

	public static void main(String[] args) {

	}

}