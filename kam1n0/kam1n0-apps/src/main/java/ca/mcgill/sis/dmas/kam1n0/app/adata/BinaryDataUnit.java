package ca.mcgill.sis.dmas.kam1n0.app.adata;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;

public class BinaryDataUnit {

	public String binaryName;
	public String binaryId;
	public String numFunctions;
	public Architecture architecture;

	public BinaryDataUnit(Binary binary) {
		binaryName = binary.binaryName;
		binaryId = Long.toString(binary.binaryId);
		numFunctions = Long.toString(binary.numFunctions);
		architecture = binary.architecture;
	}

}
