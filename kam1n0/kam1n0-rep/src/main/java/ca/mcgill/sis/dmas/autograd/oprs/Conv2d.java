package ca.mcgill.sis.dmas.autograd.oprs;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import com.fasterxml.jackson.annotation.JsonIgnore;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Tensor;
import ca.mcgill.sis.dmas.autograd.utils.Convolutions.Conv2dND;
import ca.mcgill.sis.dmas.autograd.Opr.Binop;

public class Conv2d extends Binop {

	@JsonIgnore
	private transient INDArray view;
	@JsonIgnore
	private transient INDArray kernel;
	@JsonIgnore
	private transient Conv2dND trp;
	private int s_h;
	private int s_w;

	public Conv2d(Graph g, String name, Tensor input, Tensor kernel, int stride_h, int stride_w) {
		super(g, name, input, kernel);
		this.s_h = stride_h;
		this.s_w = stride_w;
	}

	@Override
	public void calOutput() {
		trp = new Conv2dND(getA().val, getB().val, s_h, s_w);
		getOutputTensor().val = trp.conv2d();
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			return trp.dInput(getOutputTensor().grd);
		} else if (inputTensor == getB()) {
			return trp.dKernel(getOutputTensor().grd);
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

	public static void main(String[] args) {
		INDArray tensor = Nd4j.create(new double[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
				20, 21, 22, 23, 24, 25 });
		tensor = tensor.reshape(1, 5, 5, 1);
		System.out.println(tensor);
		int kw = 3, stride = 1;
		INDArray kernel = Nd4j.ones(kw, kw, 1, 1);
		Conv2dND opr = new Conv2dND(tensor, kernel, stride, stride);
		INDArray out = opr.conv2d();

		System.out.println(out);
		System.out.println(opr.dKernel(Nd4j.onesLike(out)));
		System.out.println(opr.dInput(Nd4j.onesLike(out)));
	}

}
