package ca.mcgill.sis.dmas.autograd;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.autograd.oprs.GradientOpr;

/**
 * For easy serialization and injection
 * 
 * @author Steven
 *
 */
public class Tensor {

	private static Logger logger = LoggerFactory.getLogger(Tensor.class);

	public String name;
	public String parentOpr;
	public List<String> childrenOpr = new ArrayList<>();

	public boolean isWeight = false;
	public boolean isTrainable = false;
	public boolean isCost = false;
	public INDArray val;
	public INDArray grd;
	private Graph graph;

	public Tensor(Graph graph, String name, INDArray val, boolean isWeight, boolean isTrainable) {
		this.name = name;
		this.graph = graph;
		this.val = val;
		this.isWeight = isWeight;
		this.isTrainable = isTrainable;
	}

	public Tensor(INDArray tmp) {
		val = tmp;
	}

	public Opr getParentOpr() {
		return graph.operations.get(parentOpr);
	}

	public List<Opr> getChildrenOpr() {
		return childrenOpr.stream().map(oprN -> graph.operations.get(oprN)).collect(Collectors.toList());
	}

	public void reset() {
		if (!isWeight)
			val = null;
		grd = null;
	}

	public INDArray eval() {
		if (this.graph.verbose > 1)
			logger.info("Evaluating " + name);
		if (val != null)
			return val;
		if (getParentOpr() == null) {
			logger.error("Value is null and the parent is non exist. Cannot evaluate this variable.");
		}
		getParentOpr().eval();
		if (this.graph.verbose > 1)
			logger.info("Got value from " + name);
		return val;
	}

	public INDArray grad() {
		if (this.graph.verbose > 1)
			logger.info("Tracking gradient for " + name);
		if (isCost) {
			grd = Nd4j.onesLike(val);
			return grd;
		}
		if (grd != null)
			return grd;
		grd = Nd4j.accumulate(getChildrenOpr().stream().filter(this.graph::gradientContinue).map(opr -> {
			INDArray cgrad = opr.grad(this);
			if (this.graph.verbose > 1)
				logger.info(opr.name + " " + Arrays.toString(cgrad.shape()));
			return cgrad;
		}).collect(Collectors.toList()));
		if (this.graph.verbose > 1)
			logger.info("Got grd from " + name);
		return grd;
	}

	public Tensor add(Tensor b) {
		return this.graph.add(this, b);
	}

	public Tensor hardtanh() {
		return this.graph.hardtanh(this);
	}

	public Tensor matmul(Tensor b) {
		return this.graph.matmul(this, b);
	}

	public Tensor mul(Tensor b) {
		return this.graph.mul(this, b);
	}

	public Tensor div(Tensor b) {
		return this.graph.div(this, b);
	}

	public Tensor pow(double w) {
		return this.graph.pow(this, w);
	}

	public Tensor relu() {
		return this.graph.relu(this);
	}

	public Tensor sigmoid() {
		return this.graph.sigmoid(this);
	}

	public Tensor sub(Tensor b) {
		return this.graph.sub(this, b);
	}

	public Tensor reduce_sum(int dim) {
		return this.graph.reduce_sum(this, dim);
	}

	public Tensor reduce_sum() {
		return this.graph.reduce_sum(this);
	}

	public Tensor reduce_mean(int dim) {
		return this.graph.reduce_mean(this, dim);
	}

	public Tensor reduce_mean() {
		return this.graph.reduce_mean(this);
	}

	public Tensor reduce_sum_all() {
		return this.graph.reduce_sum_all(this);
	}

	public Tensor diff_mse(Tensor truth) {
		return this.graph.diff_mse(this, truth);
	}

	public Tensor gradient() {
		return this.graph.gradient(this);
	}

	public Tensor add_inplace(Tensor b) {
		return this.graph.add_inplace(this, b);
	}

	public Tensor sub_inplace(Tensor b) {
		return this.graph.sub_inplace(this, b);
	}

	public Tensor l2() {
		return this.graph.l2(this);
	}

	public Tensor squeeze(int dim) {
		return this.graph.squeezeDim(this, dim);
	}

	public Tensor expand(int dim) {
		return this.graph.expandDim(this, dim);
	}

	public Tensor conv2d(Tensor kernel) {
		return this.graph.conv2d(this, kernel, 1, 1);
	}

	public Tensor conv2d(int in_channel, int out_channel, int kernel_h, int kernel_w, int stride_h, int stride_w) {
		return this.graph.conv2d(this, in_channel, out_channel, kernel_h, kernel_w, stride_h, stride_w);
	}

	public Tensor conv2d(Tensor kernel, int h_stride, int h_width) {
		return this.graph.conv2d(this, kernel, h_stride, h_width);
	}

	public Tensor conv1d(Tensor kernel) {
		return this.graph.conv1d(this, kernel, 1);
	}

	public Tensor conv1d(Tensor kernel, int stride) {
		return this.graph.conv1d(this, kernel, stride);
	}

	public Tensor pool2d_max(int k_h, int k_w, int stride_h, int stride_w) {
		return this.graph.pool2d_max(this, k_h, k_w, stride_h, stride_w);
	}

	public Tensor dropout(Tensor keep_prob) {
		return this.graph.dropout(this, keep_prob);
	}

	public Tensor reshape(int... shape) {
		return this.graph.reshape(this, shape);
	}

	public Tensor flatten(int dim) {
		return this.graph.flatten(this, dim);
	}

	public Tensor permute(int... indx) {
		return this.graph.permute(this, indx);
	}

	public Tensor reduce_max(int dim) {
		return this.graph.reduce_max(this, dim);
	}

	public Tensor reduce_max() {
		return this.graph.reduce_max(this);
	}

	public Tensor conv_transpose(int[] kernel_size, int stride_h, int stride_w) {
		return this.graph.conv_transpose(this, kernel_size, stride_h, stride_w);
	}

	public Tensor conv_transpose(int k_h, int k_w, int stride_h, int stride_w) {
		return this.graph.conv_transpose(this, new int[] { k_h, k_w }, stride_h, stride_w);
	}

}
