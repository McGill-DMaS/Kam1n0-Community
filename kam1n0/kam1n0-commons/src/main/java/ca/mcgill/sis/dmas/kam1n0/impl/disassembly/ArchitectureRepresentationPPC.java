/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.impl.disassembly;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Register;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LengthKeyWord;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LineFormat;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Operation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.SuffixGroup;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class ArchitectureRepresentationPPC {

	public static ArchitectureRepresentation get() {

		ArchitectureRepresentation ar = new ArchitectureRepresentation();

		SuffixGroup ux2 = new SuffixGroup("ux2", "", "u", "x");
		SuffixGroup ce1 = new SuffixGroup("ce1", "", "c", "e");
		SuffixGroup od2 = new SuffixGroup("od2", "", "o", ".");
		SuffixGroup scc1 = new SuffixGroup("scc1", "", "s", "c", "c.");
		SuffixGroup cd2 = new SuffixGroup("cd2", "", "c", ".");
		SuffixGroup d1 = new SuffixGroup("d1", "", ".");
		SuffixGroup u1 = new SuffixGroup("u1", "", "u");

		// for jmp
		SuffixGroup la2 = new SuffixGroup("la2", "", "l", "a");
		SuffixGroup lrctr = new SuffixGroup("lrctr", "", "lr", "ctr");
		SuffixGroup test1 = new SuffixGroup("test1", "", "c", "dnzf", "dzf", "f", "dnzt", "t", "dnz", "dz", "eq", "ge",
				"gt", "le", "lt", "ne", "ng", "nl", "ns", "so");
		SuffixGroup pl1 = new SuffixGroup("pl1", "", "+");

		SuffixGroup lwi3 = new SuffixGroup("lwi4", "", "l", "w", "i");

		ar.suffixGroups = new ArrayList<>(
				Arrays.asList(ux2, ce1, od2, scc1, cd2, d1, u1, la2, lrctr, test1, lwi3, pl1));

		ar.operations = new ArrayList<>();

		ar.operations.add(new Operation("lbz", ux2, ux2));
		ar.operations.add(new Operation("lhz", ux2, ux2));
		ar.operations.add(new Operation("lha", ux2, ux2));
		ar.operations.add(new Operation("lwz", ux2, ux2));
		ar.operations.add(new Operation("stb", ux2, ux2));
		ar.operations.add(new Operation("sth", ux2, ux2));
		ar.operations.add(new Operation("stw", ux2, ux2));

		ar.operations.add(new Operation("lmw"));
		ar.operations.add(new Operation("stmw"));

		ar.operations.add(new Operation("add", ce1, od2, od2));
		ar.operations.add(new Operation("addi", scc1));
		ar.operations.add(new Operation("addme", od2, od2));
		ar.operations.add(new Operation("addze", od2, od2));
		ar.operations.add(new Operation("neg", od2, od2));
		ar.operations.add(new Operation("subf", ce1, od2, od2));
		ar.operations.add(new Operation("subfic"));
		ar.operations.add(new Operation("subfme", od2, od2));
		ar.operations.add(new Operation("subfze", od2, od2));

		ar.operations.add(new Operation("and", cd2, cd2));
		ar.operations.add(new Operation("andi."));
		ar.operations.add(new Operation("andis."));
		ar.operations.add(new Operation("cntlzw", d1));
		ar.operations.add(new Operation("eqv", d1));
		ar.operations.add(new Operation("extsb", d1));
		ar.operations.add(new Operation("extsh", d1));
		ar.operations.add(new Operation("nand", d1));
		ar.operations.add(new Operation("nor", d1));
		ar.operations.add(new Operation("or", d1));
		ar.operations.add(new Operation("ori"));
		ar.operations.add(new Operation("oris"));
		ar.operations.add(new Operation("slw", d1));
		ar.operations.add(new Operation("srw", d1));
		ar.operations.add(new Operation("srawi", d1));
		ar.operations.add(new Operation("sraw", d1));
		ar.operations.add(new Operation("xor", d1));
		ar.operations.add(new Operation("xori"));
		ar.operations.add(new Operation("xoris"));

		ar.operations.add(new Operation("mulhw"));
		ar.operations.add(new Operation("muli"));
		ar.operations.add(new Operation("mulw"));

		ar.operations.add(new Operation("mr"));
		ar.operations.add(new Operation("lis"));
		ar.operations.add(new Operation("li"));
		ar.operations.add(new Operation("mflr"));
		ar.operations.add(new Operation("mtlr"));
		ar.operations.add(new Operation("mtctr"));

		ar.operations.add(new Operation("ldf"));
		ar.operations.add(new Operation("stfd"));
		ar.operations.add(new Operation("lfs"));
		ar.operations.add(new Operation("clrlwi"));

		ar.operations.add(new Operation("divw", u1, od2, od2));
		ar.operations.add(new Operation("rlwimi", d1));
		ar.operations.add(new Operation("rlwinm", d1));
		ar.operations.add(new Operation("rlwnm", d1));

		ar.operations.add(new Operation("cmp", lwi3, lwi3, lwi3));

		ar.operations.add(new Operation("crand"));
		ar.operations.add(new Operation("crandc"));
		ar.operations.add(new Operation("creqv"));
		ar.operations.add(new Operation("crnand"));
		ar.operations.add(new Operation("crnor"));
		ar.operations.add(new Operation("cror"));
		ar.operations.add(new Operation("crorc"));
		ar.operations.add(new Operation("crxor"));
		ar.operations.add(new Operation("mcrf"));
		ar.operations.add(new Operation("crclr"));
		ar.operations.add(new Operation("crmove"));
		ar.operations.add(new Operation("crnot"));
		ar.operations.add(new Operation("crset"));

		ar.operations.add(new Operation("tw"));
		ar.operations.add(new Operation("twi"));

		Arrays.asList("fdiv", "srwi", ".extern", "fmr", "nop", "not", "fadd", "lwbrx", "stfs", "rotlw", "fcmpu", "frsp",
				"fneg", "rotlwi", "slwi", "mulhwu", "fctiwz", "fabs", "fdivs", "insrwi", "extrwi", "fsub", "fmadd",
				"lfd", "clrrwi", "fmul", "mulli", "mullw", "mfcr").stream().map(str -> new Operation(str))
				.forEach(ar.operations::add);

		ar.operationJmps = new ArrayList<>();

		ar.operationJmps.add(new Operation("b", test1, lrctr, la2, la2, pl1));
		ar.operationJmps.add(new Operation("sc"));

		ar.registers = Arrays
				.asList("R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
						"R15", "R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27",
						"R28", "R29", "R30", "R31")
				.stream().map(op -> new ArchitectureRepresentation.Register(op, "GEN", 32))
				.collect(Collectors.toCollection(ArrayList::new));

		Arrays.asList("CR").stream().map(op -> new ArchitectureRepresentation.Register(op, "CND", 32))
				.forEach(ar.registers::add);

		Arrays.asList("CTR").stream().map(op -> new ArchitectureRepresentation.Register(op, "LOP", 32))
				.forEach(ar.registers::add);

		Arrays.asList("XER").stream().map(op -> new ArchitectureRepresentation.Register(op, "EXP", 32))
				.forEach(ar.registers::add);

		Arrays.asList("LR").stream().map(op -> new ArchitectureRepresentation.Register(op, "LNK", 32))
				.forEach(ar.registers::add);

		Arrays.asList("CR0", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7").stream()
				.map(op -> new Register(op, "FLG", 1)).forEach(ar.registers::add);

		ar.lengthKeywords = new ArrayList<>();
		ar.lengthKeywords.add(new LengthKeyWord("@h", 16));
		ar.lengthKeywords.add(new LengthKeyWord("@ha", 16));
		ar.lengthKeywords.add(new LengthKeyWord("@l", 16));

		ar.constantVariableRegex = "(^LOC_+)|(^loc_+)|([0-9x#\\-\\s])|^[\\S]+$";

		ar.memoryVariableRegex = "(\\([\\s\\S]+\\))";

		ar.lineFormats = new ArrayList<>(Arrays.asList(new LineFormat(
				"(?<OPT>[\\S]+)[\\s]+(?<OPN1>[\\S\\s]+)[\\s]*,[\\s]*(?<OPN2>[\\S\\s]+),[\\s]*(?<OPN3>[\\S\\s]+)", 3),
				new LineFormat("(?<OPT>[\\S]+)[\\s]+(?<OPN1>[\\S\\s]+)[\\s]*,[\\s]*(?<OPN2>[\\S\\s]+)", 2), //
				new LineFormat("(?<OPT>[\\S]+)[\\s]+(?<OPN1>[\\S\\s]+)", 1), //
				new LineFormat("(?<OPT>[\\S]+)[\\s]+", 0)));

		ar.processor = "ppc";
		ar.jmpKeywords = new ArrayList<>();
		return ar;
	}

	public static void main(String[] args) throws Exception {
		ArchitectureRepresentation ar = ArchitectureRepresentationPPC.get();
		Lines.flushToFile(Lines.from(ar.toXml()),
				KamResourceLoader.writeFile("architectures/" + ar.processor + ".xml").getAbsolutePath());

		// AsmLineNormalizationUtils.init(ar, true);
		//
		// FeatureConstructor constructor = new
		// FeatureConstructor(NormalizationLevel.NORM_TYPE,
		// FreqFeatures.getFeatureMemFreq(),
		// FreqFeatures.getFeatureMemGramFreq(2),
		// FreqFeatures.getFeatureMemOprFreq());
		//
		// constructor.featureElements.forEach(System.out::println);

		// AsmLineNormalizationResource.init(ar);

		// NormalizationSetting setting = NormalizationSetting.New()
		// .setNormalizationLevel(NormalizationLevel.NORM_TYPE_LENGTH).setNormalizeConstant(true)
		// .setNormalizeOperation(true);

		// BinarySurrogate bs = BinarySurrogate.load(new File(
		// "C:\\Users\\lynn\\Desktop\\test-ppc\\ppc\\busybox\\busybox-1.22.0\\busybox_unstripped.so.tmp0.json"));
		// List<Function> funcs = bs.toFunctions();
		//
		// HashSet<String> ms = new HashSet<>();
		// funcs.stream().flatMap(func -> func.blocks.stream()).flatMap(blk ->
		// blk.codes.stream()).forEach(line -> {
		// List<String> tline = AsmLineNormalizer.tokenizeAsmLine(line,
		// setting);
		// String nline = StringResources.JOINER_DASH.join(tline);
		// if (nline.contains(AsmLineNormalizationUtils.NORM_UNIDF)) {
		// System.out.println(line);
		// System.out.println(nline);
		// ms.add(line.get(1));
		// }
		// });
		//
		// System.out.println(ms);

		// System.out.println(
		// AsmLineNormalizationResource.operationMap.size() +
		// AsmLineNormalizationResource.operationJmps.size());

		// Lines lines =
		// Lines.fromFile("C:\\ding\\extractARM\\TranslatorArm.java");
		// final Pattern regex = Pattern.compile("\\(([\\S]+)\\s\\+");
		// TreeMultimap<String, String> patterns = TreeMultimap.create();
		//
		// lines.forEach(line -> {
		// Matcher matcher = regex.matcher(line);
		// if (matcher.find()) {
		// String key = matcher.group(1);
		// patterns.put(key, line);
		// }
		// });
		// patterns.keySet().forEach(key -> {
		// NavigableSet<String> ls = patterns.get(key);
		// if (ls.size() != 1)
		// ls.forEach(System.out::println);
		// });

	}
}
