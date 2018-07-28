package ca.mcgill.sis.dmas.autograd.oprs;

import java.util.Arrays;

import org.apache.commons.lang3.ArrayUtils;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import ca.mcgill.sis.dmas.autograd.Graph;
import ca.mcgill.sis.dmas.autograd.Opr.Unop;
import net.ericaro.neoitertools.Index;
import ca.mcgill.sis.dmas.autograd.Tensor;

public class Permute extends Unop {

	private int[] indx;

	public Permute(Graph g, String name, Tensor a, int... indx) {
		super(g, name, a);
		this.indx = indx;
	}

	@Override
	public void calOutput() {
		getA().val.permute(indx);
	}

	@Override
	public INDArray calDz(Tensor inputTensor) {
		if (inputTensor == getA()) {
			// [2,4,1,0,3]
			// [0,1,2,3,4]
			int[] rev_indx = new int[indx.length];
			for (int i = 0; i < rev_indx.length; ++i)
				rev_indx[i] = ArrayUtils.indexOf(indx, i);
			return getOutputTensor().grd.permute(rev_indx);
		}
		return Nd4j.zerosLike(inputTensor.val);
	}

}
