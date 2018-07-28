package ca.mcgill.sis.dmas.autograd;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import scala.Tuple2;

public class Gradients {

	private Graph graph;

	public Gradients(Graph g, List<Tuple2<Tensor, Tensor>> list) {
		this.graph = g;
		this.weights_and_gradient = list;
	}

	List<Tuple2<Tensor, Tensor>> weights_and_gradient = new ArrayList<>();

	public void clip_by_norm(Tensor max_norm) {
		Tensor norm = graph
				.accumulative(weights_and_gradient.stream().map(tp -> tp._2.l2()).collect(Collectors.toList()));
		Tensor ratio = norm.div(max_norm);
		weights_and_gradient = weights_and_gradient.stream().map(tp -> new Tuple2<>(tp._1, tp._2.mul(ratio)))
				.collect(Collectors.toList());
	}

	public Opr apply(Tensor lr) {
		List<Tensor> tns = weights_and_gradient.stream().map(tp -> tp._1.sub_inplace(tp._2.mul(lr)))
				.collect(Collectors.toList());
		return graph.batch(tns.toArray(new Tensor[tns.size()]));
	}

}
