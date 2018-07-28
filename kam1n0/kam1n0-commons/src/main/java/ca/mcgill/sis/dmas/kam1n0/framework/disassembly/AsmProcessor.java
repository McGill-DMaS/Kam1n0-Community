package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

public class AsmProcessor {

	public AsmRawFunctionParser parser;
	public AsmLineNormalizer normalizer;

	public AsmProcessor(ArchitectureRepresentation rep, NormalizationSetting setting) {
		AsmLineNormalizationResource res = new AsmLineNormalizationResource(rep);
		parser = new AsmRawFunctionParser(res);
		normalizer = new AsmLineNormalizer(setting, res);
	}

}
