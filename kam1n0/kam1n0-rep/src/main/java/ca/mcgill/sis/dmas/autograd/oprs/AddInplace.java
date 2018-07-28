package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class AddInplace extends Binop {

	private static Logger logger = LoggerFactory.getLogger(AddInplace.class);

	public AddInplace(Graph g, String name, Tensor a, Tensor b) {
		super(g, name, a, b);
	}

	@Override
	public void calOutput() {
		Tensor output = this.getOutputTensor();
		getA().val.addi(getB().val);
		output.val = getA().val;
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		logger.error("The AddInplace opr {} does not support derivative calculation.", name);
		return null;
	}

}
