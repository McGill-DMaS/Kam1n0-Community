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
package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import scala.Tuple2;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LengthKeyWord;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Register;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.SuffixGroup;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

public class AsmLineNormalizationResource {

	private static Logger logger = LoggerFactory.getLogger(AsmLineNormalizationResource.class);

	private static void combination(String prefix, List<? extends List<String>> groups, int depth,
			HashSet<String> result) {
		groups.get(depth).forEach(element -> {
			if (depth == groups.size() - 1) {
				result.add(prefix + element);
			} else {
				combination(prefix + element, groups, depth + 1, result);
			}
		});
	}

	// IDA API operand type enum, as defined on https://www.hex-rays.com/products/ida/support/sdkdoc/group__o__.html
	// Comments below are taken from that documentation.
	// Those constants haven't changed over several IDA version, if they ever had.
	private enum IdaApiOperandType {
		VOID(0), // No operand
		REGISTER(1), // General Register (al,ax,es,ds...)
		MEMORY(2), // Direct Memory Reference (DATA).
		MEMORY_PHRASE(3), // Memory Ref [Base Reg + Index Reg]
		MEMORY_DISPLACEMENT(4),  // Memory Ref [Base Reg + Index Reg + Displacement].
		IMMEDIATE(5), // Immediate Value (constant)
		IMMEDIATE_FAR(6), // Immediate Far Address (CODE).
		IMMEDIATE_NEAR(7), // Immediate Near Address (CODE).
		PROCESSOR_SPECIFIC_0(8), // processor specific type
		PROCESSOR_SPECIFIC_1(9), // processor specific type
		PROCESSOR_SPECIFIC_2(10), // processor specific type
		PROCESSOR_SPECIFIC_3(11), // processor specific type
		PROCESSOR_SPECIFIC_4(12), // processor specific type
		PROCESSOR_SPECIFIC_5(13); // processor specific type

		private final int value;

		IdaApiOperandType(int value) {
			this.value = value;
		}

		public static boolean isMemoryReference(int operandType) {
			return operandType >= MEMORY.value && operandType <= MEMORY_DISPLACEMENT.value;
		}

		public static boolean isImmediate(int operandType) {
			return operandType >= IMMEDIATE.value && operandType <= IMMEDIATE_NEAR.value;
		}
	}

	public static final String NORM_REG = "REG";
	public static final String NORM_MEM = "MEM";
	public static final String NORM_VAR = "VAR";
	public static final String NORM_CONST = "CNT";
	public static final String NORM_UNIDF = "UNI";

	public Pattern constantPattern;
	public Pattern memoryPattern;
	public ArchitectureRepresentation architecture;
	public ImmutableMap<String, Register> registers;
	public ImmutableMap<String, LengthKeyWord> lengthKeyWords;
	public ImmutableMap<String, String> operationMap;
	public ImmutableSet<String> operationJmps;
	public ImmutableSet<String> jmpKeywords;
	public ImmutableSet<String> clibNames;

	public static AsmLineNormalizationResource retrieve(ArchitectureType type) {
		return new AsmLineNormalizationResource(type.retrieveDefinition());
	}

	public AsmLineNormalizationResource(ArchitectureRepresentation ar) {
		architecture = ar;

		Builder<String, Register> registersBuilder = ImmutableMap.builder();
		ar.registers.stream().forEach(reg -> {reg.identifier = reg.identifier.toUpperCase(); reg.category = reg.category.toUpperCase();});
		ar.registers.forEach(reg -> registersBuilder.put(reg.identifier, reg));
		registers = registersBuilder.build();

		ar.operations.stream().forEach(opt -> opt.identifier = opt.identifier.toUpperCase());
		ar.operationJmps.stream().forEach(opt -> opt.identifier = opt.identifier.toUpperCase());

		final Map<String, SuffixGroup> suffix;
		if (ar.suffixGroups != null)
			suffix = ar.suffixGroups.stream().collect(Collectors.toMap(sg -> sg.identifier.toUpperCase(), sg -> sg));
		else
			suffix = new HashMap<>();

		final Map<String, String> opGrp;
		if (ar.oprGroups != null)
			opGrp = ar.oprGroups.stream()
					.flatMap(og -> og.oprs.stream().map(opr -> new Tuple2<>(opr.toUpperCase(), og.identifier.toUpperCase())))
					.collect(Collectors.toMap(tp -> tp._1.toUpperCase(), tp -> tp._2));

		else
			opGrp = new HashMap<>();

		Builder<String, String> optBuilder = ImmutableMap.<String, String>builder();
		Stream.concat(ar.operations.stream(), ar.operationJmps.stream()).forEach(opt -> {
			HashSet<String> suffixs_total = new HashSet<>();
			if (opt.suffixGroups != null && opt.suffixGroups.size() > 0) {
				List<ArrayList<String>> ls = opt.suffixGroups.stream().map(sgid -> suffix.get(sgid.toUpperCase()))
						.filter(sg -> sg != null).map(sg -> sg.suffixs).collect(Collectors.toList());

				combination("", ls, 0, suffixs_total);

			}
			if (suffixs_total.size() > 0)
				for (String sf : suffixs_total) {
					String idstr = opt.identifier;
					if (opGrp.containsKey(idstr.toUpperCase()))
						idstr = opGrp.get(idstr.toUpperCase());
					optBuilder.put((opt.identifier + sf).toUpperCase(), idstr);
				}
			else {
				String idstr = opt.identifier.toUpperCase();
				if (opGrp.containsKey(idstr.toUpperCase()))
					idstr = opGrp.get(idstr.toUpperCase());
				optBuilder.put(opt.identifier, idstr);
			}
		});
		operationMap = optBuilder.build();

		operationJmps = ImmutableSet.<String>builder()
				.addAll(ar.operationJmps.stream().map(opt -> opt.identifier).collect(Collectors.toList())).build();

		ar.lengthKeywords.stream().forEach(key -> key.identifier = key.identifier.toUpperCase());
		Builder<String, LengthKeyWord> keyWordBuilder = ImmutableMap.builder();
		ar.lengthKeywords.stream().forEach(keyw -> keyWordBuilder.put(keyw.identifier, keyw));
		lengthKeyWords = keyWordBuilder.build();

		constantPattern = Pattern.compile(ar.constantVariableRegex);
		memoryPattern = Pattern.compile(ar.memoryVariableRegex);

		linePatterns = ar.lineFormats.stream()
				.map(pattern -> new Tuple2<>(Pattern.compile(pattern.lineRegex), pattern.numberOfOperand))
				.collect(Collectors.toList());

		jmpKeywords = ImmutableSet.<String>builder()
				.addAll(ar.jmpKeywords.stream().map(kw -> kw.toUpperCase()).collect(Collectors.toList())).build();

		clibNames = ImmutableSet.<String>builder().addAll(LibcUtils.c_calls).build();

	}

	// in descending number of operand order:
	public static List<Tuple2<Pattern, Integer>> linePatterns;

	public Set<String> getAllOperandValues(NormalizationLevel level) {
		switch (level) {
		case NORM_ROOT:
			return Sets.newHashSet(NORM_REG, NORM_MEM);
		case NORM_TYPE: {
			HashSet<String> vals = new HashSet<>();
			vals.add(NORM_MEM);
			registers.values().stream().forEach(reg -> vals.add(reg.category.toUpperCase()));
			return vals;
		}
		case NORM_LENGTH: {
			HashSet<String> vals2 = new HashSet<>();
			vals2.add(NORM_VAR);
			lengthKeyWords.values().stream()
					.forEach(keyw -> vals2.add(NORM_VAR + StringResources.FORMAT_2R.format(keyw.length)));
			registers.values().forEach(reg -> vals2.add(NORM_VAR + StringResources.FORMAT_2R.format(reg.length)));
			return vals2;
		}
		case NORM_TYPE_LENGTH: {
			HashSet<String> vals2 = new HashSet<>();
			vals2.add(NORM_MEM);
			lengthKeyWords.values().stream()
					.forEach(keyw -> vals2.add(NORM_MEM + StringResources.FORMAT_2R.format(keyw.length)));
			registers.values().forEach(reg -> vals2.add(reg.category + StringResources.FORMAT_2R.format(reg.length)));
			return vals2;
		}
		default:
			break;
		}
		return null;
	}

	public Set<String> getALLOperations(boolean normalizeOperand) {
		if (!normalizeOperand)
			return operationMap.keySet();
		else
			return new HashSet<>(operationMap.values());

	}

	public String normalizeOperation(String operation, boolean normalizeOperation) {
		if (!normalizeOperation)
			return operation.toUpperCase();
		operation = operation.toUpperCase();
		String operationWithoutSuffix = operationMap.get(operation);
		if (operationWithoutSuffix != null)
			return operationWithoutSuffix;
		else
			return NORM_UNIDF;

	}

	public int extractLengthInfpFromOperation(String operation) {
		int length = 0;
		for (LengthKeyWord w : lengthKeyWords.values())
			if (operation.endsWith(w.identifier)) {
				length = w.length;
				break;
			}
		return length;
	}

	public String normalizeOperand(String operand, Integer oprType, NormalizationSetting.NormalizationLevel level,
			int enforcedLength, boolean normalizeConstant) {

		operand = operand.trim().toUpperCase();

		Register register = registers.get(operand);
		if (register != null)
			return normalizeRegister(level, register, enforcedLength);

		if ((oprType == null && constantPattern.matcher(operand).find())
				|| (oprType != null && IdaApiOperandType.isImmediate(oprType)))
			if (normalizeConstant)
				return NORM_CONST;
			else
				return normalizeConstant(operand);

		if ((oprType == null && memoryPattern.matcher(operand).find())
				|| (oprType != null && IdaApiOperandType.isMemoryReference(oprType)))
			return normalizeMemRef(level, operand, enforcedLength);

		// System.out.println("Discover unknown operand (treated as constant): "
		// + operand);

		return NORM_CONST;

	}

	public String[] extractParts(String rawAsmLine) {
		rawAsmLine = rawAsmLine.replaceFirst("^(0x)[0-9abcdefABCDEF]+", "").trim();

		for (int i = 0; i < linePatterns.size(); i++) {
			Matcher matcher = linePatterns.get(i)._1.matcher(rawAsmLine);
			if (matcher.find()) {
				String[] tkns = new String[linePatterns.get(i)._2 + 1];
				tkns[0] = matcher.group("OPT").toUpperCase();
				for (int j = 1; j < tkns.length; ++j)
					tkns[j] = matcher.group("OPN" + j);
				return tkns;
			}
		}
		return null;
	}

	private String normalizeMemRef(NormalizationLevel level, String operand, int enforcedLenth) {
		switch (level) {
		case NORM_NONE:
			return operand;
		case NORM_ROOT:
			return NORM_MEM;
		case NORM_TYPE:
			return NORM_MEM;
		case NORM_LENGTH:
			int length = 0;
			if (enforcedLenth > 0)
				length = enforcedLenth;
			else
				for (LengthKeyWord w : lengthKeyWords.values())
					if (operand.contains(w.identifier)) {
						length = w.length;
						break;
					}
			if (length != 0)
				return NORM_VAR + StringResources.FORMAT_2R.format(length);
			else
				return NORM_VAR;
		case NORM_TYPE_LENGTH:
			int length2 = 0;
			if (enforcedLenth > 0)
				length2 = enforcedLenth;
			else
				for (LengthKeyWord w : lengthKeyWords.values())
					if (operand.contains(w.identifier)) {
						length2 = w.length;
						break;
					}
			if (length2 != 0)
				return NORM_MEM + StringResources.FORMAT_2R.format(length2);
			else
				return NORM_MEM;
		default:
			return NORM_MEM;
		}
	}

	private String normalizeConstant(String operand) {
		return operand;
	}

	private String normalizeRegister(NormalizationSetting.NormalizationLevel level, Register register,
			int enforcedLength) {
		if (register != null) {
			switch (level) {
			case NORM_NONE:
				return register.identifier;
			case NORM_ROOT:
				return NORM_REG;
			case NORM_TYPE:
				return register.category;
			case NORM_LENGTH:
				if (enforcedLength > register.length)
					return NORM_VAR + StringResources.FORMAT_2R.format(enforcedLength);
				else
					return NORM_VAR + StringResources.FORMAT_2R.format(register.length);
			case NORM_TYPE_LENGTH:
				if (enforcedLength > register.length)
					return register.category + StringResources.FORMAT_2R.format(enforcedLength);
				else
					return register.category + StringResources.FORMAT_2R.format(register.length);
			default:
				return NORM_REG;
			}
		} else {
			logger.debug("Unidentified register: {}", register);
			return NORM_REG;
		}
	}

}
