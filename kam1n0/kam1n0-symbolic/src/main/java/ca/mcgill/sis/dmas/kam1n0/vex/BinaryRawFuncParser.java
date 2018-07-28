package ca.mcgill.sis.dmas.kam1n0.vex;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.math.NumberUtils;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.Endianness;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.InstructionSize;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.RawFunctionParser;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.graph.BinaryFunctionParser;

public class BinaryRawFuncParser implements RawFunctionParser {

	@Override
	public Binary fromPlainText(List<String> lines, String functionName, String binaryName,
			Map<String, String[]> otherParams) throws Exception {
		String bin = lines.get(0);
		String archType = otherParams.get("archType")[0];
		String endian = otherParams.get("endian")[0];
		int bit = NumberUtils.toInt(otherParams.get("bit")[0], 32);
		long addr = Long.parseUnsignedLong(otherParams.get("addr")[0].replaceAll("0x", ""), 16);

		bin = bin.replaceAll("\\s", "").toLowerCase();

		byte[] bytes = StringResources.converteByteString(bin);

		Architecture arch = new Architecture();
		arch.type = ArchitectureType.valueOf(archType);
		arch.size = bit == 64 ? InstructionSize.b64 : InstructionSize.b32;
		arch.endian = Endianness.valueOf(endian);

		Binary binary = BinaryFunctionParser.fromBinary(bytes, functionName, binaryName, addr, arch);
		return binary;
	}

}
