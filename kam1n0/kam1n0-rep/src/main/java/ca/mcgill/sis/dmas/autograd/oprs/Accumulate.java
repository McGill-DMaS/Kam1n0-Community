package ca.mcgill.sis.dmas.autograd.oprs;

import java.util.stream.Collectors;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class Accumulate extends Opr {

	public Accumulate(Graph graph, String name, Tensor... inputs) {
		super(graph, name, inputs);
	}

	@Override
	public void calOutput() {
		getOutputTensor().val = Nd4j.accumulate(
				this.inputTensorName.stream().map(nm -> graph.tensors.get(nm).val).collect(Collectors.toList()));
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (this.inputTensorName.contains(inputTensor.name))
			return getOutputTensor().grd;
		return Nd4j.zerosLike(inputTensor.val);
	}

}
