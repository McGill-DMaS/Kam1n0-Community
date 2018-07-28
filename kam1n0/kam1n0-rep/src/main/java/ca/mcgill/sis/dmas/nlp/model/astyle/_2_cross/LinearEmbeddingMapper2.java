package ca.mcgill.sis.dmas.nlp.model.astyle._2_cross;

import org.nd4j.linalg.api.ndarray.INDArray;
import ca.mcgill.sis.dmas.autograd.Gradients;
import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class LinearEmbeddingMapper2 extends EmbeddingMapper {

	private Graph g;
	private Tensor x, y, lr, z, cost;
	private Opr train_opr;

	public void init() {
		g = Graph.create().asDefault();

		x = g.var_placeholder("x");
		y = g.var_placeholder("y");
		lr = g.var_placeholder("lr");

		z = x.matmul(g.var_weight(in_dim, out_dim));
		cost = z.diff_mse(y).reduce_mean(-1);

		Gradients grd = g.all_gradients(cost);
		train_opr = grd.apply(lr);
	}

	public INDArray transform(INDArray source) {
		g.inject(x, source);
		return z.eval();
	}

	public Number cost(INDArray source, INDArray target, double lr) {
		g.reset();
		g.inject(this.x, source);
		g.inject(this.y, target);
		if (lr > 0)
			g.inject(this.lr, lr);

		double cost_val = cost.eval().getDouble(0);
		if (lr > 0) {
			train_opr.eval();
		}
		return cost_val;
	}

	public static void main(String[] args) throws Exception {
		test(LinearEmbeddingMapper2.class, 500, 0.001);
	}

}
