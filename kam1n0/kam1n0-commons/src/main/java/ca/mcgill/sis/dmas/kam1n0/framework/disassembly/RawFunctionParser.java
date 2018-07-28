package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

import java.util.List;
import java.util.Map;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;

public interface RawFunctionParser {
	public Binary fromPlainText(List<String> lines, String functionName, String binaryName,
			Map<String, String[]> otherParams) throws Exception;
}
