package ca.mcgill.sis.dmas.kam1n0.cli.dgen;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.StreamIterable;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing.Configuration;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunctionUtils;

/**
 * Parse binaries to json asm function.
 * 
 * @author dingm
 *
 */
public class DataProcessor {

	private static Logger logger = LoggerFactory.getLogger(DataProcessor.class);

	public static class SimplifiedAsmFuncFormat implements Serializable {

		private static final long serialVersionUID = -8805232949838831793L;
		public String name;
		public String bin;
		public List<String> bbs = new ArrayList<>();

		public static Iterable<SimplifiedAsmFuncFormat> convert(List<Function> asmFunctions,
				List<SrcFunction> srcFunctions, AsmLineNormalizationResource res) {

			HashMap<Long, String> srcFuncNameIdMap = new HashMap<>();

			// only interested in non-empty source function
			srcFunctions.stream().filter(srcFunc -> srcFunc.asmFuncID != -1)
					.filter(srcFunc -> StringResources.JOINER_LINE.join(srcFunc.content).trim().length() > 0)
					.forEach(srcFunc -> srcFuncNameIdMap.put(//
							srcFunc.asmFuncID, //
							srcFunc.functionName)); //
			Stream<SimplifiedAsmFuncFormat> stream = asmFunctions.stream().map(asmfunc -> {
				SimplifiedAsmFuncFormat format = new SimplifiedAsmFuncFormat();
				format.name = srcFuncNameIdMap.get(asmfunc.functionId);
				if (format.name == null) {
					logger.info("Failed to get src name for asmFunc {}. replaced with asm name.", asmfunc.functionName);
					format.name = asmfunc.functionName;
				}
				format.bin = asmfunc.binaryName;
				format.bbs = asmfunc.blocks.stream().map(blk -> {
					// skip call params
					List<String> lns = blk.codes.stream().filter(ins -> ins.size() > 0)
							.map(ins -> ins.subList(1, ins.size())).map(ins -> {
								String mem = ins.get(0).toUpperCase();
								if (res.operationJmps.contains(mem))
									return mem.toLowerCase();
								return StringResources.JOINER_TOKEN.join(ins);
							}).collect(Collectors.toList());
					return StringResources.JOINER_TOKEN.join(lns);
				}).collect(Collectors.toList());
				return format;
			}).filter(func -> func != null).filter(func -> !func.name.startsWith("sub_"))
					.filter(func -> func.bbs.size() > 50);
			return new StreamIterable<>(stream);
		}

	}

	public static void process(File confFile, String outputFile) throws Exception {
		logger.info("Loading...");
		Configuration conf = Configuration.load(confFile.getAbsolutePath());
		List<Function> funcs = Arrays.stream(new File(conf.getAsmFolderDir()).listFiles()).flatMap(file -> {
			try {
				return BinarySurrogate.load(file).toFunctions().stream();
			} catch (Exception e) {
				logger.error("Failed to load file " + file, e);
				return null;
			}
		}).collect(Collectors.toList());
		if(funcs.size() < 1) {
			logger.info("No functions to process from {}" + confFile.getAbsolutePath());
			return;
		}
		ArchitectureRepresentation ar = funcs.get(0).architecture.type.retrieveDefinition();

		ArrayList<SrcFunction> srcs = SrcFunctionUtils.readAll(new File(conf.getSrcFuncFileDir()));

		Iterable<SimplifiedAsmFuncFormat> formats = SimplifiedAsmFuncFormat.convert(funcs, srcs, new AsmLineNormalizationResource(ar));

		logger.info("Writing file...");
		ArrayList<SimplifiedAsmFuncFormat> ls = Lists.newArrayList(formats);
		Collections.sort(ls, (f1, f2) -> f1.name.compareTo(f2.name));
		ObjectMapper mapper = new ObjectMapper();
		LineSequenceWriter writer = Lines.getLineWriter(outputFile, false);
		for (SimplifiedAsmFuncFormat format : ls) {
			writer.writeLine(mapper.writeValueAsString(format));
		}
	}

	public static void main(String[] args) throws Exception {
		Environment.init();
		// Environment.loadArchitecture("metapc.xml");
		process(new File("E:/Optimizations/binaries/conf.xml"), "E:/Optimizations/binaries/all.json");
	}

}
