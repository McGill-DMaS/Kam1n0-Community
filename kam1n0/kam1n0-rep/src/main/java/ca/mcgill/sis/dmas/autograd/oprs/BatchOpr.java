package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class BatchOpr extends Opr {
	private static Logger logger = LoggerFactory.getLogger(BatchOpr.class);

	public BatchOpr(Graph graph, String name, Tensor[] inputs) {
		super(graph, name, inputs);
	}

	@Override
	public void calOutput() {
		inputTensorName.stream().forEach(nm -> graph.tensors.get(nm).eval());
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		logger.error("The AddInplace opr {} does not support derivative calculation.", name);
		return null;
	}

}
