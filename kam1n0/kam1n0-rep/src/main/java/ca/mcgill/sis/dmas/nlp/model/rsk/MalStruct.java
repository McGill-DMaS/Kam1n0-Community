package ca.mcgill.sis.dmas.nlp.model.rsk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Function;
import com.google.common.collect.Iterators;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.LibcUtils;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.FuncTokenized;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.FuncTokenized.BlockTokenized;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.Keywords;

public class MalStruct {

	private static Logger logger = LoggerFactory.getLogger(MalStruct.class);

	static Predicate<String> isInstruction = str -> ArchitectureType.metapc.retrieveRawOperations()
			.contains(str.toLowerCase());
	static Predicate<String> isRegister = str -> ArchitectureType.metapc.retrieveRawRegisters()
			.contains(str.toLowerCase());
	static Predicate<String> isConstant = str -> str.matches("^[0-9a-fA-F]+[Hh]$");
	static Predicate<String> isFuncCall = str -> LibcUtils.c_calls.contains(str.toLowerCase().replaceAll("_", ""));
	static Predicate<String> isKeyword = str -> Keywords.KW_METAPC.contains(str.toLowerCase().replaceAll("_", ""));

	static String grp_ins = "ins";
	static String grp_reg = "reg";
	static String grp_lib = "fun-libc";
	static String grp_imp = "fun-imp";
	static String grp_cns = "cns";
	static String grp_cns_str = "cns-str";
	static String grp_key = "key";
	static String grp_unk = "unk";

	public static String get_grp(String str, Set<String> fn_map) {
		if (isInstruction.test(str))
			return grp_ins;
		if (isRegister.test(str))
			return grp_reg;
		if (isFuncCall.test(str.toLowerCase().replaceAll("_", "")))
			return grp_lib.toLowerCase().replaceAll("_", "");
		if (fn_map.contains(str))
			return grp_imp;
		if (isConstant.test(str))
			return grp_cns;
		if (isKeyword.test(str))
			return grp_key;
		if (str.trim().equalsIgnoreCase("___security_cookie"))
			return grp_cns;
		if (str.startsWith("a"))
			return grp_cns_str;
		return grp_unk;
	};

	@JsonIgnoreProperties
	public static class Asm {

		@JsonProperty("name")
		public String name;
		@JsonProperty("ins")
		public List<List<String>> ins = null;

		@JsonIgnore
		BlockTokenized convert() {
			BlockTokenized bt = new BlockTokenized();
			bt.ins = ins;
			bt.id = name;
			return bt;
		}
	}

	@JsonIgnoreProperties
	public static class Sample {

		@JsonProperty("imp_f")
		public List<String> impF = null;
		@JsonProperty("sha256")
		public String sha256;
		@JsonProperty("asm")
		public List<Asm> asm = null;

		@JsonIgnore
		public FuncTokenized convert() {
			FuncTokenized ft = new FuncTokenized();
			ft.name = sha256;
			ft.id = sha256;
			ft.blks = asm.stream().map(blk -> blk.convert()).collect(Collectors.toList());
			return ft;
		}

	}

	public static List<Sample> load(String folder) throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		return Arrays.stream(new File(folder).listFiles()).parallel().filter(file -> file.getName().endsWith(".json"))
				.map(file -> {
					try {
						Sample sample = mapper.readValue(file, Sample.class);
						return sample;
					} catch (IOException e) {
						logger.error("Failed to parse " + file, e);
						return null;
					}
				}).filter(sam -> sam != null).collect(Collectors.toList());
	}

	public static Iterable<Sample> loadAsIte(String folder) throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		List<File> files = Arrays.asList(new File(folder).listFiles());
		Iterable<Sample> ite = new Iterable<Sample>() {

			@Override
			public Iterator<Sample> iterator() {
				return Iterators.filter(Iterators.transform(files.iterator(), new Function<File, Sample>() {
					@Override
					public Sample apply(File file) {
						try {
							Sample sample = mapper.readValue(file, Sample.class);
							return sample;
						} catch (IOException e) {
							logger.error("Failed to parse " + file, e);
							return null;
						}
					}
				}), x -> x != null);
			}
		};
		return ite;
	}

}
