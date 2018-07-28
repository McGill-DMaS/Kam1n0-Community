package ca.mcgill.sis.dmas.autograd;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.nd4j.linalg.api.ndarray.INDArray;

public abstract class Opr {

	/**
	 * Fill in the value of the output node
	 */
	public abstract void calOutput();

	/**
	 * Calculate derivative w.r.t. a chosen input;
	 * 
	 * @param inputTensor
	 * @return
	 */
	public abstract INDArray calDz(Tensor inputTensor);

	public List<String> inputTensorName;
	public String outputTensorName;
	public String name;
	protected Graph graph;

	protected Opr(Graph graph, String name, Tensor... inputs) {
		this.graph = graph;
		this.name = name;
		inputTensorName = Arrays.stream(inputs).map(input -> input.name).collect(Collectors.toList());
		Arrays.stream(inputs).forEach(input -> input.childrenOpr.add(name));
		Tensor outputNode = graph.var_tmp(name + "-out");
		outputNode.parentOpr = name;
		outputTensorName = outputNode.name;
	}

	public Tensor getOutputTensor() {
		return graph.tensors.get(outputTensorName);
	}

	public List<Tensor> getInputTensor() {
		return inputTensorName.stream().map(tn -> graph.tensors.get(tn)).collect(Collectors.toList());
	}

	public INDArray eval() {
		getInputTensor().stream().forEach(Tensor::eval);
		calOutput();
		return getOutputTensor().val;
	}

	/**
	 * We only cached the gradient for tensor; not opr; We assume that for a single
	 * opr the cost of getting gradient without tracing back is cheap.
	 * 
	 * @param tensor
	 * @return
	 */
	public INDArray grad(Tensor tensor) {
		this.getOutputTensor().grad();
		return calDz(tensor);
	}

	public static abstract class Binop extends Opr {

		public String a;
		public String b;

		public Tensor getA() {
			return graph.tensors.get(a);
		}

		public Tensor getB() {
			return graph.tensors.get(b);
		}

		protected Binop(Graph g, String name, Tensor a, Tensor b) {
			super(g, name, a, b);
			this.a = a.name;
			this.b = b.name;
		}

	}

	public static abstract class Unop extends Opr {

		public String a;

		public Tensor getA() {
			return graph.tensors.get(a);
		}

		protected Unop(Graph g, String name, Tensor a) {
			super(g, name, a);
			this.a = a.name;
		}

	}

	public static abstract class Triop extends Opr {

		public String a;
		public String b;
		public String c;

		public Tensor getA() {
			return graph.tensors.get(a);
		}

		public Tensor getB() {
			return graph.tensors.get(b);
		}

		public Tensor getC() {
			return graph.tensors.get(c);
		}

		protected Triop(Graph g, String name, Tensor a, Tensor b, Tensor c) {
			super(g, name, a, b, c);
			this.a = a.name;
			this.b = b.name;
			this.c = c.name;
		}

	}

}
