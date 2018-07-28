package ca.mcgill.sis.dmas.kam1n0.utils.src;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;

public class UnstrippedParser extends Parser {

	private static Logger logger = LoggerFactory.getLogger(UnstrippedParser.class);

	@Override
	public SrcInfo parseSrcFunctionAndLinkeToAssemblyFunction(String sourceCodeDir, String newSourceCodeDir,
			List<EntryPair<BinarySurrogate, File>> binaryFileAndItsCorrespondingAsmFile) {
		List<LinkInfo> infos = binaryFileAndItsCorrespondingAsmFile.stream().parallel().map(ent -> {
			// check whether the corresponding debug symbol exists:
			File symbolFile = new File(ent.value.getAbsolutePath() + this.getFileExtension());
			if (!symbolFile.exists()) {
				logger.error("The corresponding {} file {} for {} does not exist. skipping.", this.getFileExtension(),
						symbolFile.getAbsolutePath(), ent.value.getAbsolutePath());
				return null;
			}

			BinarySurrogate unstripped = DisassemblyFactory.disassembleSingle(symbolFile);
			logger.info("Parsing unstripped version: {}", unstripped.name);

			Map<Long, String> map = unstripped.functions.stream()
					.collect(Collectors.toMap(func -> func.sea, func -> func.name));

			long linked = ent.key.functions.stream().filter(func -> map.containsKey(func.sea)).peek(func -> {
				func.srcName = map.get(func.sea);
			}).count();

			LinkInfo info = new LinkInfo();
			info.linked = (int) linked;
			info.totalAsm = ent.key.functions.size();
			info.totalSrc = 0;
			// infos.add(info);
			logger.info("Linking info for {}: {}", ent.value, info.toString());
			return info;
		}).filter(info -> info != null).collect(Collectors.toList());
		SrcInfo srcInfo = new SrcInfo();
		srcInfo.linkInfo = LinkInfo.merge(infos);
		srcInfo.srcFuncs = new ArrayList<>();
		return srcInfo;
	}

	@Override
	public String getFileExtension() {
		return ".unstrip";
	}

}
