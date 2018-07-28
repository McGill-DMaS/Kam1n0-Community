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
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragmentNormalized;

public class AsmLineNormalizer {

	private static Logger logger = LoggerFactory.getLogger(AsmLineNormalizer.class);
	public static Pattern asmLineTokenizerBySpace = Pattern.compile("\\s+", Pattern.CASE_INSENSITIVE);
	public static final ImmutableList<String> emptyList = ImmutableList.<String>builder().build();

	public AsmLineNormalizationResource res;
	public NormalizationSetting setting;

	public AsmLineNormalizer(NormalizationSetting setting, AsmLineNormalizationResource res) {
		this.res = res;
		this.setting = setting;
	}

	public List<String> tokenizeAsmLine(List<String> tkns) {

		if (tkns == null)
			return emptyList;

		// less than length 2: only has segment address
		if (tkns.size() < 2)
			return emptyList;

		// add mnemonics
		ArrayList<String> rtokens = new ArrayList<>();

		String opC = tkns.get(1);
		if (opC == null) {
			logger.error("No operation in this parsed line.. {}", tkns);
			return emptyList;
		} else {
			opC = res.normalizeOperation(opC, setting.normalizeOperation);
			rtokens.add(opC.toUpperCase());
		}
		if (res.operationJmps.contains(opC))
			return rtokens;

		for (int j = 2; j < tkns.size(); ++j)
			if (tkns.get(j) == null)
				logger.error("Null parsed operand.. {} @ {}", j, tkns);
			else {
				int operationLevelLength = 0;
				if (setting.normalizationLevel == NormalizationLevel.NORM_TYPE_LENGTH
						|| setting.normalizationLevel == NormalizationLevel.NORM_TYPE_LENGTH)
					operationLevelLength = res.extractLengthInfpFromOperation(opC);
				rtokens.add(res.normalizeOperand(tkns.get(j), setting.normalizationLevel, operationLevelLength,
						setting.normalizeConstant));
			}

		// System.out.println(tkns + " ---> " + rtokens);

		return rtokens;
	}

	public Iterable<List<String>> tokenizeAsmLines(Iterable<? extends List<String>> asmlines) {
		return Iterables.transform(asmlines, line -> tokenizeAsmLine(line));
	}

	public static List<String> tokenizeAsmLineBySpace(String asmLine) {
		return Arrays.asList(asmLineTokenizerBySpace.split(asmLine, 0));
	}

	public static Iterable<String> tokenizeAsmLinesBySpace(Iterable<String> asmlines) {
		return Iterables.concat(Iterables.transform(asmlines, AsmLineNormalizer::tokenizeAsmLineBySpace));
	}

	public Iterable<AsmFragmentNormalized> tokenizeAsmFragments(Iterable<? extends AsmFragment> frags) {
		return Iterables.transform(frags, frag -> tokenizeAsmFragment(frag));
	}

	public AsmFragmentNormalized tokenizeAsmFragment(AsmFragment fra) {
		AsmFragmentNormalized nfra = new AsmFragmentNormalized(
				fra.getAsmLines().stream().map(ln -> tokenizeAsmLine(ln)).collect(Collectors.toList()));
		// nfra.forEach(System.out::println);
		// System.out.println();
		return nfra;
	}

	public static String formatCodeLine(List<String> line) {
		if (line != null && line.size() > 1) {
			String prefix = line.get(0) + StringResources.STR_TOKENBREAK + line.get(1).toUpperCase()
					+ StringResources.STR_TOKENBREAK;
			if (line.size() > 2)
				return prefix + StringResources.JOINER_TOKEN_CSV_SPACE.join(line.subList(2, line.size()));
			else
				return prefix;
		} else if (line.size() == 1)
			return line.get(0);
		else
			return StringResources.STR_EMPTY;
	}

	public static void main(String[] args) {
		// System.out.println(StringResources.JOINER_TOKEN.join(tokenize(
		// "4200764 cmp byte ptr [edx+0D9h], 0 ",
		// NormalizationLevel.NORM_REG_SPECIFIC)));
		//
		// Iterable<String> tokens = AsmLineNormalizer.tokenizeAsmLines(Arrays
		// .asList("4200764 cmp byte ptr [edx+0D9h], 0 ;sdfwerwcwerc",
		// "4200765 cmp byte ptr [edx+0D9h], 0 ",
		// "4200766 cmp byte ptr [edx+0D9h], 0 ",
		// "4200767 cmp byte ptr [edx+0D9h], 0 ",
		// "4200767 retn 0ch "),
		// NormalizationSetting.NormalizationLevel.NORM_LENGTH);
		// for (String string : tokens) {
		// System.out.println(string);
		// }
	}
}
