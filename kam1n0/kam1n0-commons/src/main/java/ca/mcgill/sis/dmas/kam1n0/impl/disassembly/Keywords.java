package ca.mcgill.sis.dmas.kam1n0.impl.disassembly;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class Keywords {
	public static Set<String> KW_METAPC = Arrays
			.asList("dword", "word", "byte", "qword", "xmmword", "ymmword", "ptr", "large", "dst")
			.stream().map(str -> str.toLowerCase()).collect(Collectors.toSet());

}
