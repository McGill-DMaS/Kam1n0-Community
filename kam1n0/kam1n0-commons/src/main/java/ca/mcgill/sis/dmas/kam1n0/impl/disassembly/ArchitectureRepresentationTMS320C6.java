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
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LengthKeyWord;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LineFormat;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Operation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.SuffixGroup;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class ArchitectureRepresentationTMS320C6 {

	public static ArchitectureRepresentation get() {

		// some binaries:
		// http://processors.wiki.ti.com/index.php/Example_application_using_DSP_Link_on_OMAPL1x
		// manual used:
		// http://www.ti.com/lit/ug/sprugh7/sprugh7.pdf

		// after running this script and generating the .xml file (check for errors)
		// we need to add new architecture name into
		// /kam1n0-commons/src/main/java/ca/mcgill/sis/dmas/kam1n0/commons/defs/Architecture.java$ArchitectureType
		// so the system can recognize it.
		// also we need to add it to the UI of asm-clone:
		// /kam1n0-apps/src/main/resources/templates/apps/clone/asm-clone/confg.html

		// all definitions below are case-insensitive.

		ArchitectureRepresentation ar = new ArchitectureRepresentation();

		// we can append "", "2", "DP", or "SP" to "ABS"
		// so we have new instructions e.g. ABS2 ABSSP
		// these operations can be normalized into "ABS"
		ar.addOperation("ABS", "", "2", "DP", "SP");
		ar.addOperation("ADD", "", "2", "4", "AB", "AD", "AH", "AW", "DP", "K", "KPC", "SP", "SUB", "SUB2", "U");
		ar.addOperation("AND", "", "N");
		ar.addOperation("AVG", "", "2", "U4");
		ar.addOperation("BIT", "", "C", "R");
		ar.addOperation("CLR");
		ar.addOperation("CMP", "", "EQ", "EQ2", "EQ4", "EQDP", "EQSP", "GT", "GT2", "GTDP", "GTSP", "GTU", "GTU4", "LT",
				"LT2", "LTDP", "LTSP", "LTU", "LTU4", "Y", "YR", "YR1");
		ar.addOperation("DDOT", "P4", "PH2", "PH2R", "PL2", "PL2R");
		ar.addOperation("DEAL");
		ar.addOperation("DINT");
		ar.addOperation("DMV");
		ar.addOperation("DOTP", "2", "N2", "NRSU2", "NRUS2", "RSU2", "RUS2", "SU4", "U4", "US4");
		ar.addOperation("DP", "ACK2", "ACKX2", "INT", "SP", "TRUNC");
		ar.addOperation("EXT", "", "U");
		ar.addOperation("GMPY", "", "4");
		ar.addOperation("INT", "DP", "DPU", "SP", "SPU");
		ar.addOperation("LD", "B", "BU", "DW", "H", "HU", "NDW", "NW", "W");
		ar.addOperation("MAX", "2", "U4");
		ar.addOperation("MIN", "2", "U4");
		ar.addOperation("MPY", "", "2", "2IR", "32", "32SU", "32U", "32US", "DP", "H", "HI", "HIR", "HL", "HLU", "HSLU",
				"HSU", "HU", "HULS", "HUS", "I", "ID", "IH", "IHR", "IL", "ILR", "LH", "LHU", "LI", "LIR", "LSHU",
				"LUHS", "SP", "SP2DP", "SPDP", "SU", "SU4", "U", "U4", "US", "US4");
		ar.addOperation("MV", "", "C", "D", "K", "KH", "KL", "KLH");
		ar.addOperation("NEG");
		ar.addOperation("NOP");
		ar.addOperation("NORM");
		ar.addOperation("NOT");
		ar.addOperation("PACK", "2", "H2", "H4", "HL2", "L4", "LH2");
		ar.addOperation("RCP", "DP", "SP");
		ar.addOperation("RINT");
		ar.addOperation("ROTL");
		ar.addOperation("RPACK2");
		ar.addOperation("RSQR", "DP", "SP");
		ar.addOperation("SAD", "D", "D2", "DSU2", "DSUB", "DSUB2", "DU4", "DUS2");
		ar.addOperation("SAT");
		ar.addOperation("SET");
		ar.addOperation("SH", "FL", "FL3", "L", "LMB", "R", "R2", "RMB", "RU", "RU2");
		ar.addOperation("SMPY", "", "2", "32", "H", "HL", "LH");
		// single point conversion
		ar.addOperation("SP", "ACK2", "ACKU4", "DP", "INT", "KERNEL", "KERNELR", "LOOP", "LOOPD", "LOOPW", "MASK",
				"MASKR", "TRUNC");
		ar.addOperation("SS", "HL", "HVL", "HVR", "UB", "UB2");
		ar.addOperation("ST", "B", "BU", "DW", "H", "HU", "NDW", "NW", "W");
		ar.addOperation("SUB", "", "2", "4", "AB", "ABS4", "AH", "AW", "C", "DP", "SP", "U");
		ar.addOperation("SW", "AP2", "AP4", "E", "ENR");
		ar.addOperation("UNPK", "HU4", "LU4");
		ar.addOperation("XOR", "", "MPY");
		ar.addOperation("XPND", "2", "4");
		ar.addOperation("ZERO");

		ar.addJmpOperation("B", "", "DEC", "NOP", "POS");
		ar.addJmpOperation("CALLP");

		// end of operations

		// registers that with uknown or unique grouping.
		ar.registers.add(new Register("AMR", "AMR", 32));
		ar.registers.add(new Register("CSR", "CSR", 32));
		ar.registers.add(new Register("ACR", "ACR", 32));
		ar.registers.add(new Register("ADR", "ADR", 32));
		ar.registers.add(new Register("PCE1", "PCE1", 32));
		ar.registers.add(new Register("REP", "REP", 32));
		ar.registers.add(new Register("DNUM", "DNUM", 32));
		ar.registers.add(new Register("SSR", "SSR", 32));
		ar.registers.add(new Register("CS", "CS", 32));
		ar.registers.add(new Register("DS", "DS", 32));

		// general purpose register
		Arrays.asList("A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14",
				"A15", "A16", "A17", "A18", "A19", "A20", "A21", "A22", "A23", "A24", "A25", "A26", "A27", "A28", "A29",
				"A30", "A31", "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11", "B12", "B13",
				"B14", "B15", "B16", "B17", "B18", "B19", "B20", "B21", "B22", "B23", "B24", "B25", "B26", "B27", "B28",
				"B29", "B30", "B31").stream().map(idt -> new Register(idt, "GEN", 32))
				.forEach(reg -> ar.registers.add(reg));

		// interrupt register
		Arrays.asList("IFR", "ISR", "ICR", "IER", "ISTP", "IRP").stream().map(idt -> new Register(idt, "INT", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Time Stamp register
		Arrays.asList("TSCL", "TSCH").stream().map(idt -> new Register(idt, "TIM", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Loop count register
		Arrays.asList("ILC", "RILC").stream().map(idt -> new Register(idt, "LOP", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Polynomial related
		Arrays.asList("GPLYA", "GPLYB", "GFPGFR").stream().map(idt -> new Register(idt, "POL", 32))
				.forEach(reg -> ar.registers.add(reg));

		// State related
		Arrays.asList("TSR", "ITSR", "NTSR").stream().map(idt -> new Register(idt, "STA", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Exception related
		Arrays.asList("ECR", "EFR", "IERR").stream().map(idt -> new Register(idt, "STA", 32))
				.forEach(reg -> ar.registers.add(reg));

		ar.constantVariableRegex = "(^[0-9]+)|(^=)|#+|(LOC_+)|(loc_+)";

		ar.memoryVariableRegex = "(\\[[\\s\\S]+\\])|(\\{[\\s\\S]+\\})";

		// address operation operand1, operrand2; comments
		ar.lineFormats = new ArrayList<>(Arrays.asList(new LineFormat(
				"(?<OPT>[\\S]+)[\\s]+(?<OPN1>\\{*\\[*([^\\{\\}\\]\\[]+)\\}*\\]*!*)[\\s]*,[\\s]*(?<OPN2>\\{*\\[*[^\\{\\}\\[\\]]+\\}*\\]*!*),[\\s]*(?<OPN3>\\[*\\{*[^\\{\\[\\]\\}]+\\}*\\]*!*),[\\s]*(?<OPN4>\\[*\\{*[^\\{\\[\\]\\}]+\\}*\\]*!*)",
				4),
				new LineFormat(
						"(?<OPT>[\\S]+)[\\s]+(?<OPN1>\\{*\\[*([^\\{\\}\\]\\[]+)\\}*\\]*!*)[\\s]*,[\\s]*(?<OPN2>\\{*\\[*[^\\{\\}\\[\\]]+\\}*\\]*!*),[\\s]*(?<OPN3>\\[*\\{*[^\\{\\[\\]\\}]+\\}*\\]*!*)",
						3),
				new LineFormat(
						"(?<OPT>[\\S]+)[\\s]+(?<OPN1>\\{*\\[*([^\\{\\}\\]\\[]+)\\}*\\]*!*)[\\s]*,[\\s]*(?<OPN2>\\{*\\[*[^\\{\\}\\[\\]]+\\}*\\]*!*)",
						2),
				new LineFormat("(?<OPT>[\\S]+)[\\s]+(?<OPN1>\\{*\\[*([^\\{\\}\\]\\[]+)\\}*\\]*!*)", 1),

				new LineFormat("(?<OPT>[\\S]+)[\\s]+", 0)));

		ar.processor = "tms320c6";
		ar.jmpKeywords = new ArrayList<>();
		return ar;
	}

	public static void main(String[] args) throws Exception {
		ArchitectureRepresentation ar = ArchitectureRepresentationTMS320C6.get();
		Lines.flushToFile(Lines.from(ar.toXml()),
				KamResourceLoader.writeFile("architectures/" + ar.processor + ".xml").getAbsolutePath());
		AsmLineNormalizationResource.retrieve(ArchitectureType.tms320c6);

		// AsmLineNormalizationUtils.init(ar, true);
		//
		// FeatureConstructor constructor = new
		// FeatureConstructor(NormalizationLevel.NORM_TYPE,
		// FreqFeatures.getFeatureMemFreq(),
		// FreqFeatures.getFeatureMemGramFreq(2),
		// FreqFeatures.getFeatureMemOprFreq());
		//
		// constructor.featureElements.forEach(System.out::println);
		//
		// AsmLineNormalizationResource.init(ar);
		//
		// System.out.println(
		// AsmLineNormalizationResource.operationMap.size() +
		// AsmLineNormalizationResource.operationJmps.size());

		// NormalizationSetting setting = NormalizationSetting.New()
		// .setNormalizationLevel(NormalizationLevel.NORM_TYPE_LENGTH).setNormalizeConstant(true)
		// .setNormalizeOperation(true);
		//
		// BinarySurrogate bs = BinarySurrogate.load(new File(
		// "C:\\Users\\lynn\\Desktop\\test-arm\\busybox\\busybox-1.24.0\\busybox_unstripped.so.tmp0.json"));
		// List<Function> funcs = bs.toFunctions();
		//
		// funcs.stream().flatMap(func -> func.blocks.stream()).flatMap(blk ->
		// blk.codes.stream()).forEach(line -> {
		// List<String> tline = AsmLineNormalizer.tokenizeAsmLine(line,
		// setting);
		// String nline = StringResources.JOINER_DASH.join(tline);
		// if (nline.contains(AsmLineNormalizationUtils.NORM_UNIDF)) {
		// System.out.println(line);
		// System.out.println(nline);
		// }
		// });

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
