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

public class ArchitectureRepresentationARM {

	public static ArchitectureRepresentation get() {

		ArchitectureRepresentation ar = new ArchitectureRepresentation();

		SuffixGroup suffixConditions = new SuffixGroup("condition", "", "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL",
				"VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV");

		SuffixGroup suffixUpdateFlag = new SuffixGroup("updateFlag", "", "S");

		SuffixGroup suffixSize = new SuffixGroup("size", "", "B", "SB", "H", "SH", "D");

		SuffixGroup suffixSizeDot = new SuffixGroup("sizeDot", "", ".W");

		SuffixGroup suffixSizeNoDot = new SuffixGroup("sizeNoDot", "", "W");

		SuffixGroup suffixSizeNoDotAndDot = new SuffixGroup("sizeNoDotAndDot", "", ".W", "W");

		SuffixGroup suffixmultiRegisterInstructions = new SuffixGroup("multiInstruction", "", "DA", "DB", "IA", "IB",
				"EA", "FA", "FD", "ED");

		SuffixGroup suffixAdditionalSWP = new SuffixGroup("additionalSWP", "", "B");
		SuffixGroup suffixAdditionalLDSTR = new SuffixGroup("additionalLDSTR", "", "T");
		SuffixGroup suffixITIfElseThen = new SuffixGroup("ITIfElseThen", "", "T", "E");

		ar.suffixGroups = new ArrayList<>(Arrays.asList(suffixConditions, suffixUpdateFlag, suffixSize, suffixSizeDot,
				suffixmultiRegisterInstructions, suffixAdditionalSWP, suffixITIfElseThen, suffixSizeNoDot,
				suffixSizeNoDotAndDot));

		ar.operations = new ArrayList<>();

		Arrays.asList("ADRL", "ALIGN", "AST", "BX", "BXJ", "CDP", "CPS", "CPY", "DCB", "DCD", "DCS", "DCW", "EQUB",
				"EQUD", "EQUS", "EQUW", "LDC", "LDREX", "MCR", "MCRR", "MRC", "MRRC", "MRS", "MSR", "PKHBT", "PKHTB",
				"PLD", "QADD", "QADD16", "QADD8", "QADDSUBX", "QASX", "QDADD", "QDSUB", "QSAX", "QSUB", "QSUB16",
				"QSUBADDX", "QSUb8", "REV", "REV16", "REVSH", "RFE", "SADD16", "SADD8", "SADDSUBX", "SASX", "SEL",
				"SETEND", "SHADD16", "SHADD8", "SHADDSUBX", "SHASX", "SHSAX", "SHSUB16", "SHSUB8", "SHSUBADDX", "SMLAD",
				"SMLALD", "SMLALXY", "SMLAWY", "SMLAXY", "SMLSD", "SMLSDX", "SMLSLD", "SMLSLDX", "SMMLA", "SMMLAR",
				"SMMLS", "SMMLSR", "SMUAD", "SMUADX", "SMULWY", "SMULXY", "SMUSD", "SMUSDX", "SRS", "SSAT", "SSAT16",
				"SSAX", "SSUB16", "SSUB8", "SSUBADDX", "STC", "STREX", "SUBW", "SWI", "SXTAB16", "SXTAH", "SXTB16",
				"THUMBADC", "THUMBADCS", "THUMBADD", "THUMBADDS", "THUMBADDW", "THUMBADR", "THUMBAND", "THUMBANDS",
				"THUMBASR", "THUMBASRS", "THUMBB", "THUMBBIC", "THUMBBICS", "THUMBBKPT", "THUMBBL", "THUMBBLX",
				"THUMBBX", "THUMBCMN", "THUMBCMP", "THUMBCPS", "THUMBCPY", "THUMBEOR", "THUMBEORS", "THUMBLDMIA",
				"THUMBLSL", "THUMBLSLS", "THUMBLSR", "THUMBLSRS", "THUMBMOV", "THUMBMOVS", "THUMBMUL", "THUMBMULS",
				"THUMBMVNS", "THUMBNEG", "THUMBNEGS", "THUMBNOP", "THUMBORR", "THUMBORRS", "THUMBPOP", "THUMBPUSH",
				"THUMBREV", "THUMBREV16", "THUMBREVSH", "THUMBRORS", "THUMBSBCS", "THUMBSETEND", "THUMBSTMIA",
				"THUMBSUB", "THUMBSUBS", "THUMBSWI", "THUMBSXTB", "THUMBSXTH", "THUMBTST", "THUMBUXTB", "THUMBUXTH",
				"UADD16", "UADD8", "UADDSUBX", "UASX", "UHADD16", "UHADD8", "UHADDSUBX", "UHASX", "UHSAX", "UHSUB16",
				"UHSUB8", "UHSUBADDX", "UMAAL", "UQADD16", "UQADD8", "UQADDSUBX", "UQASX", "UQSAX", "UQSUB16", "UQSUB8",
				"UQSUBADDX", "USAD8", "USADA8", "USAT", "USAT16", "USAX", "USUB16", "USUB8", "USUBADDX", "UXTAB",
				"UXTAB16", "UXTB16").stream().map(opt -> new Operation(opt.toUpperCase(), suffixConditions))
				.forEach(ar.operations::add);

		ar.operations.add(new Operation("ADC", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("ADD", suffixConditions, suffixUpdateFlag, suffixSizeNoDotAndDot));
		ar.operations.add(new Operation("ADR", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("AND", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("ASR", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("BFC", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("BFI", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("BIC", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("CLZ", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("CMN", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("CMP", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("EOR", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("LDM", suffixConditions, suffixmultiRegisterInstructions, suffixSizeDot));
		ar.operations.add(new Operation("LDRHT", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("LDRSHT", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("LSL", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("LSR", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("MLA", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("MLS", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("MOV", suffixConditions, suffixUpdateFlag, suffixSizeNoDotAndDot));
		ar.operations.add(new Operation("MOVT", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("MUL", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("MVN", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("ORN", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("ORR", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("RBIT", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("ROR", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("RRX", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("RSB", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("RSC", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SBC", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SBFX", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SDIV", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SMLAL", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SMMUL", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("SMMULR", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("STM", suffixConditions, suffixmultiRegisterInstructions, suffixSizeDot));
		ar.operations.add(new Operation("STRHT", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SUB", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("SWP", suffixConditions, suffixAdditionalSWP));
		ar.operations.add(new Operation("SXTAB", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("SXTB", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("SXTH", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("TBB", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("TBH", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("TEQ", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("THUMBLDR", suffixConditions, suffixSize));
		ar.operations.add(new Operation("THUMBSTR", suffixConditions, suffixSize));
		ar.operations.add(new Operation("TST", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("UBFX", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("UDIV", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("UMLAL", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("UMULL", suffixConditions, suffixUpdateFlag, suffixSizeDot));
		ar.operations.add(new Operation("UXTAH", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("UXTB", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("UXTH", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("LDR", suffixConditions, suffixSize, suffixSizeDot, suffixAdditionalLDSTR));
		ar.operations.add(new Operation("STR", suffixConditions, suffixSize, suffixSizeDot, suffixAdditionalLDSTR));
		ar.operations.add(new Operation("NEG", suffixConditions, suffixUpdateFlag));
		ar.operations.add(new Operation("POP", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("PUSH", suffixConditions, suffixSizeDot));
		ar.operations.add(new Operation("SVC"));
		ar.operations.add(new Operation("NOP", suffixSizeDot));
		ar.operations.add(new Operation("SMULL"));
		ar.operations.add(new Operation("IMPORT"));
		ar.operations.add(new Operation("IT", suffixITIfElseThen, suffixITIfElseThen, suffixITIfElseThen));

		ar.operationJmps = new ArrayList<>();
		ar.operationJmps.add(new Operation("B", suffixConditions, suffixSizeDot));
		ar.operationJmps.add(new Operation("BL", suffixConditions));
		ar.operationJmps.add(new Operation("CBZ"));
		ar.operationJmps.add(new Operation("CBNZ"));
		ar.operationJmps.add(new Operation("BLX"));
		ar.operationJmps.add(new Operation("RET"));

		ar.registers = Arrays
				.asList("R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
						"R15", "R0!", "R1!", "R2!", "R3!", "R4!", "R5!", "R6!", "R7!", "R8!", "R9!", "R10!", "R11!",
						"R12!", "R13!", "R14!", "R15!")
				.stream().map(op -> new ArchitectureRepresentation.Register(op, "GEN", 32))
				.collect(Collectors.toCollection(ArrayList::new));

		Arrays.asList("SP", "SP!").stream().map(op -> new ArchitectureRepresentation.Register(op, "STA", 32))
				.forEach(ar.registers::add);

		Arrays.asList("IP", "IP!", "OP", "OP!").stream()
				.map(op -> new ArchitectureRepresentation.Register(op, "OIP", 32)).forEach(ar.registers::add);

		Arrays.asList("LR", "LR!").stream().map(op -> new ArchitectureRepresentation.Register(op, "LNK", 32))
				.forEach(ar.registers::add);

		Arrays.asList("PC", "PC!").stream().map(op -> new ArchitectureRepresentation.Register(op, "PCN", 32))
				.forEach(ar.registers::add);

		Arrays.asList("CPSR", "SPSR", "CPSR_GE", "CPSR_M", "CPSR!", "SPSR!", "CPSR_GE!", "CPSR_M!").stream()
				.map(op -> new ArchitectureRepresentation.Register(op, "PSR", 32)).forEach(ar.registers::add);

		Arrays.asList("Z", "C", "V", "Q", "E", "T", "J",

				"A", "I", "F", "CPSR_GE_0", "CPSR_GE_1", "CPSR_GE_2", "CPSR_GE_3").stream()
				.map(op -> new Register(op, "FLG", 1)).forEach(ar.registers::add);

		ar.lengthKeywords = new ArrayList<>();
		ar.lengthKeywords.add(new LengthKeyWord(".W", 16));

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

		ar.processor = "arm";
		ar.jmpKeywords = new ArrayList<>();
		return ar;
	}

	public static void main(String[] args) throws Exception {
		ArchitectureRepresentation ar = ArchitectureRepresentationARM.get();
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
