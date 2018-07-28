package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep;

import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecFullKeyCalculator;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecObject;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;

public class VecObjectArray implements VecObject<VecInfoArray, VecInfoSharedArray> {

	private static final long serialVersionUID = 4992193348261665505L;

	public double[] vals;
	public long identifier;

	public VecObjectArray(double[] vals, long identifier) {
		this.vals = vals;
		this.identifier = identifier;
	}

	@Override
	public long getUniqueHash() {
		return HashUtils.constructID(DmasByteOperation.getBytes(this.vals));
	}

	@Override
	public VecFullKeyCalculator getFullKeyCalculator(HashSchema hashSchema) {
		return () -> hashSchema.hash(vals);
	}

	@Override
	public VecInfoSharedArray getSharedInfo() {
		return new VecInfoSharedArray(this.vals);
	}

	@Override
	public VecInfoArray getSelfInfo() {
		return new VecInfoArray(identifier);
	}

	@Override
	public byte[] hash(HashSchema schema) {
		return schema.hash(vals);
	}

}
