package ca.mcgill.sis.dmas.autograd;

import org.nd4j.linalg.api.ndarray.INDArray;

public class Example {

	private static Opr train_opr;
	private static INDArray x_val;
	private static INDArray y_val;
	private static INDArray val;
	private static INDArray mn_val;
	private static INDArray l2_val;
	private static INDArray kp_val;

	public static void main(String[] args) {

		Graph g = Graph.create().asDefault();

		Tensor x = g.var_placeholder("x");
		Tensor y = g.var_placeholder("y");
		Tensor lr = g.var_placeholder("learning_rate");
		Tensor mn = g.var_placeholder("max_norm");
		Tensor l2 = g.var_placeholder("l2_normalizer_weight");
		Tensor kp = g.var_placeholder("keep_prob");
		Tensor tmp, z;

		tmp = x //
				.conv2d(1, 32, 3, 3, 1, 1)//
				.add(g.var_weight("b0", 32))//
				.relu()//
				.pool2d_max(2, 2, 2, 2)//
				.dropout(kp);

		tmp = tmp //
				.conv2d(32, 64, 3, 3, 1, 1)//
				.add(g.var_weight("b1", 64))//
				.relu()//
				.pool2d_max(2, 2, 2, 2)//
				.dropout(kp);

		tmp = tmp //
				.conv2d(64, 128, 3, 3, 1, 1)//
				.add(g.var_weight("b2", 32))//
				.relu()//
				.pool2d_max(2, 2, 2, 2)//
				.dropout(kp);

		z = tmp//
				.flatten(1)//
				.matmul(g.var_weight(4 * 4 * 32, 28 * 28));

		Tensor cost = z//
				.diff_mse(y)//
				.reduce_mean(-1)//
				.add(g.l2().mul(l2));

		Gradients grd = g.all_gradients(cost);
		grd.clip_by_norm(mn);
		train_opr = grd.apply(lr);

		g.inject(x, x_val).inject(y, y_val).inject(lr, val).inject(mn, mn_val).inject(l2, l2_val).inject(kp, kp_val);

		double cost_val = cost.eval().getDouble(0);
		train_opr.eval();

	}

}
