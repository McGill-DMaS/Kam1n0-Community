package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class GradientOpr extends Unop {

	private static Logger logger = LoggerFactory.getLogger(GradientOpr.class);

	public GradientOpr(Graph g, String name, Tensor a) {
		super(g, name, a);
	}

	@Override
	public void calOutput() {
		Tensor output = this.getOutputTensor();
		output.val = getA().grad();
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		logger.error("The gradient opr {} does not support derivative calculation.", name);
		return null;
	}

}
