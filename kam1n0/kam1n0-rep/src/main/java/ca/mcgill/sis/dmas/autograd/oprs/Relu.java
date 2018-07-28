package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.indexing.conditions.GreaterThan;
import org.nd4j.linalg.ops.transforms.Transforms;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;

public class Relu extends Unop {

	public Relu(Graph g, String name, Tensor a) {
		super(g, name, a);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = Transforms.relu(getA().val);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		// quick hack:
		// x[x<=0] = 0
		// x[x>0] = 1
		if (inputTensor == getA())
			return getA().val.cond(new GreaterThan(0)).mul(getOutputTensor().grd);
		return Nd4j.zerosLike(inputTensor.val);
	}

}
