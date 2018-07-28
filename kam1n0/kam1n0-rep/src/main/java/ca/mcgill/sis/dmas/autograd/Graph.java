package ca.mcgill.sis.dmas.autograd;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.api.rng.Random;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.oprs.Accumulate;
import ca.mcgill.sis.dmas.autograd.oprs.Add;
import ca.mcgill.sis.dmas.autograd.oprs.AddInplace;
import ca.mcgill.sis.dmas.autograd.oprs.BatchOpr;
import ca.mcgill.sis.dmas.autograd.oprs.Conv2d;
import ca.mcgill.sis.dmas.autograd.oprs.ConvolutionTranspose;
import ca.mcgill.sis.dmas.autograd.oprs.Div;
import ca.mcgill.sis.dmas.autograd.oprs.Dropout;
import ca.mcgill.sis.dmas.autograd.oprs.ExpandDim;
import ca.mcgill.sis.dmas.autograd.oprs.Flatten;
import ca.mcgill.sis.dmas.autograd.oprs.GradientOpr;
import ca.mcgill.sis.dmas.autograd.oprs.HardTanh;
import ca.mcgill.sis.dmas.autograd.oprs.Matmul;
import ca.mcgill.sis.dmas.autograd.oprs.Mul;
import ca.mcgill.sis.dmas.autograd.oprs.Permute;
import ca.mcgill.sis.dmas.autograd.oprs.Pow;
import ca.mcgill.sis.dmas.autograd.oprs.ReduceMax;
import ca.mcgill.sis.dmas.autograd.oprs.ReduceMean;
import ca.mcgill.sis.dmas.autograd.oprs.ReduceSum;
import ca.mcgill.sis.dmas.autograd.oprs.ReduceSumAll;
import ca.mcgill.sis.dmas.autograd.oprs.Relu;
import ca.mcgill.sis.dmas.autograd.oprs.Reshape;
import ca.mcgill.sis.dmas.autograd.oprs.Sigmoid;
import ca.mcgill.sis.dmas.autograd.oprs.SqueezeDim;
import ca.mcgill.sis.dmas.autograd.oprs.Sub;
import ca.mcgill.sis.dmas.autograd.oprs.SubInplace;
import jnr.ffi.Struct.intptr_t;
import scala.Tuple2;

public class Graph {

	int verbose = 0;

	private Random rand;

	private static ThreadLocal<Graph> localGraph = new ThreadLocal<>();

	public boolean gradientContinue(Opr opr) {
		if (opr instanceof GradientOpr || opr instanceof AddInplace || opr instanceof SubInplace
				|| opr instanceof BatchOpr)
			return false;
		return true;
	}

	public static Graph getDefault() {
		return localGraph.get();
	}

	public static Graph create() {
		return new Graph();
	}

	public Graph asDefault() {
		localGraph.set(this);
		return this;
	}

	public Graph() {
		this.rand = Nd4j.getRandomFactory().getNewRandomInstance(12l);
	}

	public Graph inject(Tensor tensor, INDArray array) {
		tensor.val = array;
		return this;
	}

	public Graph inject(Tensor tensor, double[][] array) {
		tensor.val = Nd4j.create(array);
		return this;
	}

	public Graph inject(Tensor tensor, double val) {
		tensor.val = Nd4j.scalar(val);
		return this;
	}

	public HashMap<String, Opr> operations = new HashMap<>();
	public HashMap<String, Tensor> tensors = new HashMap<>();

	public void reset() {
		tensors.values().parallelStream().forEach(Tensor::reset);
	}

	private Tensor addTensor(Tensor ten) {
		tensors.put(ten.name, ten);
		return ten;
	}

	public Opr addOpr(Opr opr) {
		operations.put(opr.name, opr);
		return opr;
	}

	synchronized String getDefaultOprName(Class<? extends Opr> cls) {
		return cls.getSimpleName() + operations.size();
	}

	synchronized String getDefaultTensorName(String type) {
		return type + "_" + tensors.size();
	}

	public Tensor var_weight(String name, int... shape) {
		INDArray vals = rand.nextGaussian(shape);
		return addTensor(new Tensor(this, name, vals, true, true));
	}

	public Tensor var_weight(int... shape) {
		return var_weight(getDefaultTensorName("weight"), shape);
	}

	public Tensor var_placeholder(String name) {
		return addTensor(new Tensor(this, name, null, false, false));
	}

	public Tensor var_placeholder() {
		return var_placeholder(getDefaultTensorName("placeholder"));
	}

	public Tensor var_constant(String name, double[][] vals) {
		return addTensor(new Tensor(this, name, Nd4j.create(vals), false, true));
	}

	public Tensor var_constant(String name, double val) {
		return addTensor(new Tensor(this, name, Nd4j.scalar(val), false, true));
	}

	public Tensor var_constant(double[][] vals) {
		return var_constant(getDefaultTensorName("const"), vals);
	}

	public Tensor var_constant(String name, INDArray vals) {
		return addTensor(new Tensor(this, name, vals, false, true));
	}

	public Tensor var_constant(INDArray vals) {
		return var_constant(getDefaultTensorName("const"), vals);
	}

	public Tensor var_tmp(String name) {
		return addTensor(new Tensor(this, name, null, false, false));
	}

	public Tensor add(Tensor a, Tensor b) {
		return addOpr(new Add(this, getDefaultOprName(Add.class), a, b)).getOutputTensor();
	}

	public Tensor hardtanh(Tensor a) {
		return addOpr(new HardTanh(this, getDefaultOprName(HardTanh.class), a)).getOutputTensor();
	}

	public Tensor matmul(Tensor a, Tensor b) {
		return addOpr(new Matmul(this, getDefaultOprName(Matmul.class), a, b)).getOutputTensor();
	}

	public Tensor mul(Tensor a, Tensor b) {
		return addOpr(new Mul(this, getDefaultOprName(Mul.class), a, b)).getOutputTensor();
	}

	public Tensor div(Tensor a, Tensor b) {
		return addOpr(new Div(this, getDefaultOprName(Div.class), a, b)).getOutputTensor();
	}

	public Tensor pow(Tensor a, double w) {
		return addOpr(new Pow(this, getDefaultOprName(Pow.class), a, w)).getOutputTensor();
	}

	public Tensor relu(Tensor a) {
		return addOpr(new Relu(this, getDefaultOprName(Relu.class), a)).getOutputTensor();
	}

	public Tensor sigmoid(Tensor a) {
		return addOpr(new Sigmoid(this, getDefaultOprName(Sigmoid.class), a)).getOutputTensor();
	}

	public Tensor sub(Tensor a, Tensor b) {
		return addOpr(new Sub(this, getDefaultOprName(Sub.class), a, b)).getOutputTensor();
	}

	public Tensor reduce_sum(Tensor a, int dim) {
		return addOpr(new ReduceSum(this, getDefaultOprName(ReduceSum.class), a, dim)).getOutputTensor();
	}

	public Tensor reduce_sum_all(Tensor a) {
		return addOpr(new ReduceSumAll(this, getDefaultOprName(ReduceSumAll.class), a)).getOutputTensor();
	}

	public Tensor reduce_sum(Tensor a) {
		return reduce_sum(a, -1);
	}

	public Tensor reduce_mean(Tensor a, int dim) {
		return addOpr(new ReduceMean(this, getDefaultOprName(ReduceMean.class), a, dim)).getOutputTensor();
	}

	public Tensor reduce_mean(Tensor a) {
		return reduce_mean(a, -1);
	}

	public Tensor reduce_max(Tensor a, int dim) {
		return addOpr(new ReduceMax(this, getDefaultOprName(ReduceMax.class), a, dim)).getOutputTensor();
	}

	public Tensor reduce_max(Tensor a) {
		return reduce_max(a, -1);
	}

	public Tensor conv_transpose(Tensor a, int[] kernel_size, int stride_h, int stride_w) {
		return addOpr(new ConvolutionTranspose(this, getDefaultOprName(ConvolutionTranspose.class), a, kernel_size,
				stride_h, stride_w)).getOutputTensor();
	}

	public Tensor accumulative(List<Tensor> tensors) {
		return addOpr(
				new Accumulate(this, getDefaultOprName(Accumulate.class), tensors.toArray(new Tensor[tensors.size()])))
						.getOutputTensor();
	}

	public Tensor expandDim(Tensor a, int dim) {
		return addOpr(new ExpandDim(this, getDefaultOprName(ExpandDim.class), a, dim)).getOutputTensor();
	}

	public Tensor squeezeDim(Tensor a, int dim) {
		return addOpr(new SqueezeDim(this, getDefaultOprName(SqueezeDim.class), a, dim)).getOutputTensor();
	}

	public Tensor reshape(Tensor a, int... shape) {
		return addOpr(new Reshape(this, getDefaultOprName(Reshape.class), a, shape)).getOutputTensor();
	}

	public Tensor permute(Tensor a, int... indx) {
		return addOpr(new Permute(this, getDefaultOprName(Permute.class), a, indx)).getOutputTensor();
	}

	public Tensor conv2d(Tensor input, Tensor kernel, int stride_h, int stride_w) {
		return addOpr(new Conv2d(this, getDefaultOprName(Conv2d.class), input, kernel, stride_h, stride_w))
				.getOutputTensor();
	}

	public Tensor conv2d(Tensor input, int in_channel, int out_channel, int kernel_h, int kernel_w, int stride_h,
			int stride_w) {
		Tensor kernel = this.var_weight(kernel_h, kernel_w, in_channel, out_channel);
		return conv2d(input, kernel, stride_h, stride_w);
	}

	public Tensor conv1d(Tensor input, int in_channel, int out_channel, int kernel_w, int stride) {
		input = input.expand(1);
		Tensor output = conv2d(input, in_channel, out_channel, 1, kernel_w, 1, stride);
		return output.squeeze(1);
	}

	public Tensor pool2d_max(Tensor input, int k_h, int k_w, int stride_h, int stride_w) {
		// [batch, out_height, out_width, kernel_height, kernel_width, channel]
		Tensor view = input.conv_transpose(k_h, k_w, stride_h, stride_w);
		// [batch, out_height, out_width, channel, kernel_height, kernel_width]
		view = view.permute(0, 1, 2, 5, 3, 4);
		// [batch, out_height, out_width, channel]
		Tensor max = view.reduce_max(4);
		return max;
	}

	public Tensor dropout(Tensor input, Tensor keep_prob) {
		return addOpr(new Dropout(this, getDefaultOprName(Dropout.class), input, keep_prob)).getOutputTensor();
	}

	public Tensor flatten(Tensor input, int dim) {
		return addOpr(new Flatten(this, getDefaultOprName(Flatten.class), input, dim)).getOutputTensor();
	}

	public Tensor conv1d(Tensor input, Tensor kernel, int stride) {
		input = input.expand(1);
		kernel = kernel.expand(0);
		Tensor output = conv2d(input, kernel, 1, stride);
		return output.squeeze(1);
	}

	public Tensor gradient(Tensor a) {
		return addOpr(new GradientOpr(this, getDefaultOprName(GradientOpr.class), a)).getOutputTensor();
	}

	public Tensor add_inplace(Tensor a, Tensor b) {
		return addOpr(new AddInplace(this, getDefaultOprName(AddInplace.class), a, b)).getOutputTensor();
	}

	public Tensor sub_inplace(Tensor a, Tensor b) {
		return addOpr(new SubInplace(this, getDefaultOprName(SubInplace.class), a, b)).getOutputTensor();
	}

	public Opr batch(Tensor... tensors) {
		return addOpr(new BatchOpr(this, getDefaultOprName(BatchOpr.class), tensors));
	}

	public Tensor diff_mse(Tensor logits, Tensor truth) {
		Tensor diff = sub(logits, truth);
		Tensor p_diff = pow(diff, 2);
		return reduce_mean(p_diff, -1);
	}

	public Tensor diff_cosine(Tensor logits, Tensor truth) {
		Tensor nl = logits.div(logits.l2());
		Tensor nt = truth.div(truth.l2());
		return nl.mul(nt).reduce_mean(-1);
	}

	public Tensor l2(Tensor val) {
		return val.pow(2).reduce_sum_all().pow(0.5);
	}

	public Gradients all_gradients(Tensor cost) {
		cost.isCost = true;
		List<Tensor> weights = tensors.values().stream().filter(tensor -> tensor.isWeight && tensor.isTrainable)
				.collect(Collectors.toList());
		return new Gradients(this,
				weights.stream().map(tensor -> new Tuple2<>(tensor, tensor.gradient())).collect(Collectors.toList()));
	}

	public Tensor l2() {
		List<Tensor> weights = tensors.values().stream().filter(tensor -> tensor.isWeight && tensor.isTrainable)
				.collect(Collectors.toList());
		return this.accumulative(weights.stream().map(w -> w.l2()).collect(Collectors.toList()));
	}

	// INDArray transformed = transform(inputVal);
	// Number cst = cost.apply(transformed, truth);
	// if (lr > 0) {
	// INDArray dz = cost.prop(transformed, truth);
	// for (Opr opr : oprs)
	// dz = opr.prop(dz, lr);
	// }
	// return cst;

}