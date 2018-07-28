package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep;

import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecInfoShared;

public class VecInfoSharedArray extends VecInfoShared {
	private static final long serialVersionUID = -432946420904913125L;
	public double[] vec;

	public VecInfoSharedArray() {
	}

	public VecInfoSharedArray(double[] vec) {
		this.vec = vec;
	}

}
