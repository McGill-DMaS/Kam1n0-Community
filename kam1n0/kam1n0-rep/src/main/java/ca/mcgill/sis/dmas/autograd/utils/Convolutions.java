package ca.mcgill.sis.dmas.autograd.utils;

import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.convolution.Convolution;
import org.nd4j.linalg.factory.Nd4j;

public class Convolutions {

	public static class Conv2dView {
		protected int batch, in_h, in_w, out_h, out_w, p_h, p_w, k_h, k_w, stride_h, stride_w;

		public Conv2dView(int[] input_shape, int[] kernel_shape, int stride_h, int stride_w) {
			this.batch = input_shape[0];
			this.in_h = input_shape[1];
			this.in_w = input_shape[2];

			this.k_h = kernel_shape[0];
			this.k_w = kernel_shape[1];

			this.stride_h = stride_h;
			this.stride_w = stride_w;

			this.out_h = (int) Math.ceil(in_h / ((double) stride_h));
			this.out_w = (int) Math.ceil(in_w / ((double) stride_w));
			this.p_h = ((out_h - 1) * stride_h + k_h - in_h) / 2;
			this.p_w = ((out_w - 1) * stride_w + k_w - in_w) / 2;

		}

		/**
		 * 
		 * @param input
		 *            [batch, in_height, in_width, channel]
		 * @return [batch, out_height, out_width, kernel_height, kernel_width, channel]
		 */
		public INDArray transpose(INDArray input) {
			int channel = input.shape()[3];
			input = input.permute(0, 3, 1, 2);
			INDArray col = Nd4j.createUninitialized(new int[] { batch, channel, k_h, k_w, out_h, out_w }, 'c');
			Convolution.im2col(input, k_h, k_w, stride_h, stride_w, p_h, p_w, true, col);
			return col.permute(0, 4, 5, 2, 3, 1);
		}

		/**
		 * 
		 * @param output
		 *            [batch, out_height, out_width, kernel_height, kernel_width,
		 *            in_channel]
		 * @return [batch, in_height, in_width, in_channel]
		 */
		public INDArray reverse(INDArray output) {
			int channel = output.shape()[5];
			output = output.permute(0, 5, 3, 4, 1, 2);
			INDArray im = Nd4j.create(new int[] { batch, channel, in_h, in_w }, 'c');
			Convolution.col2im(output, im, stride_h, stride_w, p_h, p_w, in_h, in_w,1,1);
			return im;
		}

	}

	public static class Conv2dND extends Conv2dView {
		private int in_ch;
		private int out_ch;
		private INDArray input;
		private INDArray kernel_2d;
		private INDArray val;

		public Conv2dND(INDArray input, INDArray kernel, int stride_h, int stride_w) {
			super(input.shape(), kernel.shape(), stride_h, stride_w);
			this.out_ch = kernel.shape()[3];
			this.in_ch = kernel.shape()[2];
			this.input = input;
			this.kernel_2d = kernel.reshape(k_h * k_w * in_ch, out_ch);
		}

		public INDArray conv2d() {
			val = transpose(this.input);
			// System.out.println(val);
			val = val.reshape(batch * out_h * out_w, k_h * k_w * in_ch);
			return val.mmul(this.kernel_2d).reshape(batch, out_h, out_w, out_ch);
		}

		public INDArray dKernel(INDArray dz) {
			dz = dz.reshape(batch * out_h * out_w, out_ch);
			INDArray dKernel = val.transpose().mmul(dz);
			return dKernel.reshape(k_h, k_w, in_ch, out_ch);
		}

		public INDArray dInput(INDArray dz) {
			dz = dz.reshape(batch * out_h * out_w, out_ch);
			// [batch * out_h * out_w, k_h * k_w * in_ch]
			INDArray dInput = dz.mmul(kernel_2d.transpose());
			dInput = dInput.reshape(batch, out_h, out_w, k_h, k_w, in_ch);
			return reverse(dInput);
		}
	}

}
