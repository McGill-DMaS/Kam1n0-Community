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

import org.eclipse.cdt.utils.AR;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Register;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LengthKeyWord;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LineFormat;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Operation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.SuffixGroup;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class ArchitectureRepresentation6502 {

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

		// operations
		Arrays.asList("BRK", "LDY", "CPY", "CPX", "ORA", "AND", "EOR", "ADC", "STA", "LDA", "CMP", "SBC", "LDX", "BIT",
										 "STY", "ASL", "ROL", "LSR", "ROR", "STX", "DEC", "INC", "PHP", "CLC", "PLP", "SEC", "PHA", "CLI",
										 "PLA", "SEI", "DEY", "TYA", "TAY", "CLV", "INY", "CLD", "INX", "SED", "TXA", "TXS", "TAX", "DEX",
										 "NOP", "TSX").stream().map(opt -> new Operation(opt.toUpperCase())).forEach(ar.operations::add);

		// branching
		Arrays.asList("BPL", "JMP", "JSR", "BMI", "RTI", "BVC", "RTS", "BVS", "BCC", "BCS", "BEQ", "BNE")
										.stream().map(opt -> new Operation(opt.toUpperCase())).forEach(ar.operations::add);

		// registers
		ar.registers.add(new Register("X", "X", 8));
		ar.registers.add(new Register("Y", "Y", 8));
		ar.registers.add(new Register("SR", "SR", 8));
		ar.registers.add(new Register("SP", "SP", 8));
		ar.registers.add(new Register("PC", "PC", 16));
		ar.registers.add(new Register("A", "AC", 8));

		// (^[0-9]+) - any character except numbers, one or more times
		// (^=) - any character except '='
		ar.constantVariableRegex = "(^[0-9]+)|(^=)|#+|(LOC_+)|(loc_+)";

		// \\ - backslash
		// \s - white space character
		// \S - non-white space character
		ar.memoryVariableRegex = "(\\[[\\s\\S]+\\])|(\\{[\\s\\S]+\\})";

		// address operation operand1, operrand2; comments
		// 0 operands
		// OPC - (?<OPT>[\\S]+)[\\s]+
		// 1 operand
		// OPC A -(?<OPT>[\\S]+[\\s]+)(?<OPN1>[\\S]+)
		// OPC $LLHH - (?<OPT>[\\S]+[\\s]+)(?<OPN1>\\$[\\S]+)
		// OPC #$BB - (?<OPT>[\\S]+[\\s]+)(?<OPN1>#\\$[\\S]+)
		// OPC ($LLHH) - (?<OPT>[\\S]+[\\s]+)(?<OPN1>\\(\\$[\\S]+\\))
		// 2 operands
		// OPC $LLHH, X - (?<OPT>[\\S]+[\\s]+)(?<OPN1>\\$[\\S]+[\\s]*,[\\s]+)(?<OPN2>[\\S]+)
		// OPC ($LL, X) - (?<OPT>[\\S]+[\\s]+)(?<OPN1>\\(\\$[\\S]+[\\s]*,[\\s]+)(?<OPN2>[\\S]+[\\s]*\\))
		// OPC ($LL), Y - (?<OPT>[\\S]+[\\s]+)(?<OPN1>\\(\\$[\\S]+\\)[\\s]*,[\\s]+)(?<OPN2>[\\S]+)
		ar.lineFormats = new ArrayList<>(Arrays.asList(
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>\\$[\\S]+[\\s]*,[\\s]+)(?<OPN2>[\\S]+)", 2),
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>\\(\\$[\\S]+[\\s]*,[\\s]+)(?<OPN2>[\\S]+[\\s]*\\))", 2),
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>\\(\\$[\\S]+\\)[\\s]*,[\\s]+)(?<OPN2>[\\S]+)", 2),
				
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>[\\S]+)", 1),
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>\\$[\\S]+)", 1),
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>#\\$[\\S]+)", 1),
				new LineFormat("(?<OPT>[\\S]+[\\s]+)(?<OPN1>\\(\\$[\\S]+\\))", 1),

				new LineFormat("(?<OPT>[\\S]+)[\\s]+", 0)));

		ar.processor = "c6502";
		ar.jmpKeywords = new ArrayList<>();
		return ar;
	}

	public static void main(String[] args) throws Exception {
		ArchitectureRepresentation ar = ArchitectureRepresentationMC68.get();
		Lines.flushToFile(Lines.from(ar.toXml()),
				KamResourceLoader.writeFile("architectures/" + ar.processor + ".xml").getAbsolutePath());
		AsmLineNormalizer normalizer = new AsmLineNormalizer(new NormalizationSetting(),
				ArchitectureType.c6502.retrieveNormalizationResource());
		System.out.println(normalizer.tokenizeAsmLine(Arrays.asList("", "fddiv.l", "d0", "a0")));
	}
}
