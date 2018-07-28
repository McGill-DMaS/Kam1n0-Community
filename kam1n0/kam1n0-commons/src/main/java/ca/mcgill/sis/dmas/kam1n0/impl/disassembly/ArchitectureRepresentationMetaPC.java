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
import ca.mcgill.sis.dmas.res.KamResourceLoader;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LengthKeyWord;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.LineFormat;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation.Operation;

public class ArchitectureRepresentationMetaPC {

	public static ArchitectureRepresentation get() {

		ArchitectureRepresentation ar = new ArchitectureRepresentation();

		ar.operations = Arrays.asList("MOV", "MOVZX", "MOVSX", "MOVSS", "XCHG", "STC", "CLC", "CMC", "STD", "CLD",
				"STI", "CLI", "PUSH", "PUSHF", "PUSHA", "POP", "POPF", "POPA", "CBW", "CWD", "CWDE", "CSQ", "IN", "OUT",
				"ADD", "ADC", "SUB", "SBB", "DIV", "IDIV", "MUL", "IMUL", "INC", "DEC", "CMP", "SAL", "SAR", "RCL",
				"RCR", "ROL", "ROR", "NEG", "NOT", "AND", "OR", "XOR", "SHL", "SHR", "NOP", "LEA", "INT", "TEST",
				"cmpxchg", "bswap", "xadd", "invd", "wbinvd", "invlpg", "rdmsr", "wrmsr", "cpuid", "cmpxchg8b", "rdtsc",
				"rsm", "cmova", "cmovb", "cmovbe", "cmovg", "cmovge", "cmovl", "cmovle", "cmovnb", "cmovno", "cmovnp",
				"cmovns", "cmovnz", "cmovo", "cmovp", "cmovs", "cmovz", "fcmovb", "fcmove", "fcmovbe", "fcmovu",
				"fcmovnb", "fcmovne", "fcmovnbe", "fcmovnu", "fcomi", "fucomi", "fcomip", "fucomip", "rdpmc", "fld",
				"fst", "fstp", "fxch", "fild", "fist", "fistp", "fbld", "fbstp", "fadd", "faddp", "fiadd", "fsub",
				"fsubp", "fisub", "fsubr", "fsubrp", "fisubr", "fmul", "fmulp", "fimul", "fdiv", "fdivp", "fidiv",
				"fdivr", "fdivrp", "fidivr", "fsqrt", "fscale", "fprem", "frndint", "fxtract", "fabs", "fchs", "fcom",
				"fcomp", "fcompp", "ficom", "ficomp", "ftst", "fxam", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1",
				"fldz", "fld1", "fldpi", "fldl2t", "fldl2e", "fldlg2", "fldln2", "finit", "fninit", "fsetpm", "fldcw",
				"fstcw", "fnstcw", "fstsw", "fnstsw", "fclex", "fnclex", "fstenv", "fnstenv", "fldenv", "fsave",
				"fnsave", "frstor", "fincstp", "fdecstp", "ffree", "fnop", "feni", "fneni", "fdisi", "fndisi", "fprem1",
				"fsincos", "fsin", "fcos", "fucom", "fucomp", "fucompp", "setalc", "svdc", "rsdc", "svldt", "rsldt",
				"svts", "rsts", "icebp", "loadall", "emms", "movd", "movq", "packsswb", "packssdw", "packuswb", "paddb",
				"paddw", "paddd", "paddsb", "paddsw", "paddusb", "paddusw", "pand", "pandn", "pcmpeqb", "pcmpeqw",
				"pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd", "pmaddwd", "pmulhw", "pmullw", "por", "psllw", "pslld",
				"psllq", "psraw", "psrad", "psrlw", "psrld", "psrlq", "psubb", "psubw", "psubd", "psubsb", "psubsw",
				"psubusb", "psubusw", "punpckhbw", "punpckhwd", "punpckhdq", "punpcklbw", "punpcklwd", "punpckldq",
				"pxor", "fxsave", "fxrstor", "sysenter", "sysexit", "pavgusb", "pfadd", "pfsub", "pfsubr", "pfacc",
				"pfcmpge", "pfcmpgt", "pfcmpeq", "pfmin", "pfmax", "pi2fd", "pf2id", "pfrcp", "pfrsqrt", "pfmul",
				"pfrcpit1", "pfrsqit1", "pfrcpit2", "pmulhrw", "femms", "prefetch", "prefetchw", "addps", "addss",
				"andnps", "andps", "cmpps", "cmpss", "comiss", "cvtpi2ps", "cvtps2pi", "cvtsi2ss", "cvtss2si",
				"cvttps2pi", "cvttss2si", "divps", "divss", "ldmxcsr", "maxps", "maxss", "minps", "minss", "movaps",
				"movhlps", "movhps", "movlhps", "movlps", "movmskps", "movups", "mulps", "mulss", "orps", "rcpps",
				"rcpss", "rsqrtps", "rsqrtss", "shufps", "sqrtps", "sqrtss", "stmxcsr", "subps", "subss", "ucomiss",
				"unpckhps", "unpcklps", "xorps", "pavgb", "pavgw", "pextrw", "pinsrw", "pmaxsw", "pmaxub", "pminsw",
				"pminub", "pmovmskb", "pmulhuw", "psadbw", "pshufw", "maskmovq", "movntps", "movntq", "prefetcht0",
				"prefetcht1", "prefetcht2", "prefetchnta", "sfence", "cmpeqps", "cmpltps", "cmpleps", "cmpunordps",
				"cmpneqps", "cmpnltps", "cmpnleps", "cmpordps", "cmpeqss", "cmpltss", "cmpless", "cmpunordss",
				"cmpneqss", "cmpnltss", "cmpnless", "cmpordss", "pf2iw", "pfnacc", "pfpnacc", "pi2fw", "pswapd",
				"fstp1", "fcom2", "fcomp3", "fxch4", "fcomp5", "ffreep", "fxch7", "fstp8", "fstp9", "addpd", "addsd",
				"andnpd", "andpd", "clflush", "cmppd", "cmpsd", "comisd", "cvtdq2pd", "cvtdq2ps", "cvtpd2dq",
				"cvtpd2pi", "cvtpd2ps", "cvtpi2pd", "cvtps2dq", "cvtps2pd", "cvtsd2si", "cvtsd2ss", "cvtsi2sd",
				"cvtss2sd", "cvttpd2dq", "cvttpd2pi", "cvttps2dq", "cvttsd2si", "divpd", "divsd", "lfence",
				"maskmovdqu", "maxpd", "maxsd", "mfence", "minpd", "minsd", "movapd", "movdq2q", "movdqa", "movdqu",
				"movhpd", "movlpd", "movmskpd", "movntdq", "movnti", "movntpd", "movq2dq", "movsd", "movupd", "mulpd",
				"mulsd", "orpd", "paddq", "pause", "pmuludq", "pshufd", "pshufhw", "pshuflw", "pslldq", "psrldq",
				"psubq", "punpckhqdq", "punpcklqdq", "shufpd", "sqrtpd", "sqrtsd", "subpd", "subsd", "ucomisd",
				"unpckhpd", "unpcklpd", "xorpd", "syscall", "sysret", "swapgs", "movddup", "movshdup", "movsldup",
				"movsxd", "cmpxchg16b", "addsubpd", "addsubps", "haddpd", "haddps", "hsubpd", "hsubps", "monitor",
				"mwait", "fisttp", "lddqu", "psignb", "psignw", "psignd", "pshufb", "pmulhrsw", "pmaddubsw", "phsubsw",
				"phaddsw", "phaddw", "phaddd", "phsubw", "phsubd", "palignr", "pabsb", "pabsw", "pabsd", "vmcall",
				"vmclear", "vmlaunch", "vmresume", "vmptrld", "vmptrst", "vmread", "vmwrite", "vmxoff", "vmxon", "ud2",
				"rdtscp", "pfrcpv", "pfrsqrtv", "cmpeqpd", "cmpltpd", "cmplepd", "cmpunordpd", "cmpneqpd", "cmpnltpd",
				"cmpnlepd", "cmpordpd", "cmpeqsd", "cmpltsd", "cmplesd", "cmpunordsd", "cmpneqsd", "cmpnltsd",
				"cmpnlesd", "cmpordsd", "blendpd", "blendps", "blendvpd", "blendvps", "dppd", "dpps", "extractps",
				"insertps", "movntdqa", "mpsadbw", "packusdw", "pblendvb", "pblendw", "pcmpeqq", "pextrb", "pextrd",
				"pextrq", "phminposuw", "pinsrb", "pinsrd", "pinsrq", "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw", "pminsb",
				"pminsd", "pminud", "pminuw", "pmovsxbw", "pmovsxbd", "pmovsxbq", "pmovsxwd", "pmovsxwq", "pmovsxdq",
				"pmovzxbw", "pmovzxbd", "pmovzxbq", "pmovzxwd", "pmovzxwq", "pmovzxdq", "pmuldq", "pmulld", "ptest",
				"roundpd", "roundps", "roundsd", "roundss", "crc32", "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm",
				"pcmpgtq", "popcnt", "extrq", "insertq", "movntsd", "movntss", "lzcnt", "xgetbv", "xrstor", "xsave",
				"xsetbv", "getsec", "clgi", "invlpga", "skinit", "stgi", "vmexit", "vmload", "vmmcall", "vmrun",
				"vmsave", "invept", "invvpid", "movbe", "aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc",
				"aeskeygenassist", "pclmulqdq", "retnw", "retnd", "retnq", "retfw", "retfd", "retfq", "rdrand", "adcx",
				"adox", "andn", "bextr", "blsi", "blsmsk", "blsr", "bzhi", "clac", "mulx", "pdep", "pext", "rorx",
				"sarx", "shlx", "shrx", "stac", "tzcnt", "xsaveopt", "invpcid", "rdseed", "rdfsbase", "rdgsbase",
				"wrfsbase", "wrgsbase", "vaddpd", "vaddps", "vaddsd", "vaddss", "vaddsubpd", "vaddsubps", "vaesdec",
				"vaesdeclast", "vaesenc", "vaesenclast", "vaesimc", "vaeskeygenassist", "vandnpd", "vandnps", "vandpd",
				"vandps", "vblendpd", "vblendps", "vblendvpd", "vblendvps", "vbroadcastf128", "vbroadcasti128",
				"vbroadcastsd", "vbroadcastss", "vcmppd", "vcmpps", "vcmpsd", "vcmpss", "vcomisd", "vcomiss",
				"vcvtdq2pd", "vcvtdq2ps", "vcvtpd2dq", "vcvtpd2ps", "vcvtph2ps", "vcvtps2dq", "vcvtps2pd", "vcvtps2ph",
				"vcvtsd2si", "vcvtsd2ss", "vcvtsi2sd", "vcvtsi2ss", "vcvtss2sd", "vcvtss2si", "vcvttpd2dq",
				"vcvttps2dq", "vcvttsd2si", "vcvttss2si", "vdivpd", "vdivps", "vdivsd", "vdivss", "vdppd", "vdpps",
				"vextractf128", "vextracti128", "vextractps", "vfmadd132pd", "vfmadd132ps", "vfmadd132sd",
				"vfmadd132ss", "vfmadd213pd", "vfmadd213ps", "vfmadd213sd", "vfmadd213ss", "vfmadd231pd", "vfmadd231ps",
				"vfmadd231sd", "vfmadd231ss", "vfmaddsub132pd", "vfmaddsub132ps", "vfmaddsub213pd", "vfmaddsub213ps",
				"vfmaddsub231pd", "vfmaddsub231ps", "vfmsub132pd", "vfmsub132ps", "vfmsub132sd", "vfmsub132ss",
				"vfmsub213pd", "vfmsub213ps", "vfmsub213sd", "vfmsub213ss", "vfmsub231pd", "vfmsub231ps", "vfmsub231sd",
				"vfmsub231ss", "vfmsubadd132pd", "vfmsubadd132ps", "vfmsubadd213pd", "vfmsubadd213ps", "vfmsubadd231pd",
				"vfmsubadd231ps", "vfnmadd132pd", "vfnmadd132ps", "vfnmadd132sd", "vfnmadd132ss", "vfnmadd213pd",
				"vfnmadd213ps", "vfnmadd213sd", "vfnmadd213ss", "vfnmadd231pd", "vfnmadd231ps", "vfnmadd231sd",
				"vfnmadd231ss", "vfnmsub132pd", "vfnmsub132ps", "vfnmsub132sd", "vfnmsub132ss", "vfnmsub213pd",
				"vfnmsub213ps", "vfnmsub213sd", "vfnmsub213ss", "vfnmsub231pd", "vfnmsub231ps", "vfnmsub231sd",
				"vfnmsub231ss", "vgatherdps", "vgatherdpd", "vgatherqps", "vgatherqpd", "vhaddpd", "vhaddps", "vhsubpd",
				"vhsubps", "vinsertf128", "vinserti128", "vinsertps", "vlddqu", "vldmxcsr", "vmaskmovdqu", "vmaskmovpd",
				"vmaskmovps", "vmaxpd", "vmaxps", "vmaxsd", "vmaxss", "vminpd", "vminps", "vminsd", "vminss", "vmovapd",
				"vmovaps", "vmovd", "vmovddup", "vmovdqa", "vmovdqu", "vmovhlps", "vmovhpd", "vmovhps", "vmovlhps",
				"vmovlpd", "vmovlps", "vmovmskpd", "vmovmskps", "vmovntdq", "vmovntdqa", "vmovntpd", "vmovntps",
				"vmovntsd", "vmovntss", "vmovq", "vmovsd", "vmovshdup", "vmovsldup", "vmovss", "vmovupd", "vmovups",
				"vmpsadbw", "vmulpd", "vmulps", "vmulsd", "vmulss", "vorpd", "vorps", "vpabsb", "vpabsd", "vpabsw",
				"vpackssdw", "vpacksswb", "vpackusdw", "vpackuswb", "vpaddb", "vpaddd", "vpaddq", "vpaddsb", "vpaddsw",
				"vpaddusb", "vpaddusw", "vpaddw", "vpalignr", "vpand", "vpandn", "vpavgb", "vpavgw", "vpblendd",
				"vpblendvb", "vpblendw", "vpbroadcastb", "vpbroadcastd", "vpbroadcastq", "vpbroadcastw", "vpclmulqdq",
				"vpcmpeqb", "vpcmpeqd", "vpcmpeqq", "vpcmpeqw", "vpcmpestri", "vpcmpestrm", "vpcmpgtb", "vpcmpgtd",
				"vpcmpgtq", "vpcmpgtw", "vpcmpistri", "vpcmpistrm", "vperm2f128", "vperm2i128", "vpermd", "vpermilpd",
				"vpermilps", "vpermpd", "vpermps", "vpermq", "vpextrb", "vpextrd", "vpextrq", "vpextrw", "vpgatherdd",
				"vpgatherdq", "vpgatherqd", "vpgatherqq", "vphaddd", "vphaddsw", "vphaddw", "vphminposuw", "vphsubd",
				"vphsubsw", "vphsubw", "vpinsrb", "vpinsrd", "vpinsrq", "vpinsrw", "vpmaddubsw", "vpmaddwd",
				"vpmaskmovd", "vpmaskmovq", "vpmaxsb", "vpmaxsd", "vpmaxsw", "vpmaxub", "vpmaxud", "vpmaxuw", "vpminsb",
				"vpminsd", "vpminsw", "vpminub", "vpminud", "vpminuw", "vpmovmskb", "vpmovsxbd", "vpmovsxbq",
				"vpmovsxbw", "vpmovsxdq", "vpmovsxwd", "vpmovsxwq", "vpmovzxbd", "vpmovzxbq", "vpmovzxbw", "vpmovzxdq",
				"vpmovzxwd", "vpmovzxwq", "vpmuldq", "vpmulhrsw", "vpmulhuw", "vpmulhw", "vpmulld", "vpmullw",
				"vpmuludq", "vpor", "vpsadbw", "vpshufb", "vpshufd", "vpshufhw", "vpshuflw", "vpsignb", "vpsignd",
				"vpsignw", "vpslld", "vpslldq", "vpsllq", "vpsllvd", "vpsllvq", "vpsllw", "vpsrad", "vpsravd", "vpsraw",
				"vpsrld", "vpsrldq", "vpsrlq", "vpsrlvd", "vpsrlvq", "vpsrlw", "vpsubb", "vpsubd", "vpsubq", "vpsubsb",
				"vpsubsw", "vpsubusb", "vpsubusw", "vpsubw", "vptest", "vpunpckhbw", "vpunpckhdq", "vpunpckhqdq",
				"vpunpckhwd", "vpunpcklbw", "vpunpckldq", "vpunpcklqdq", "vpunpcklwd", "vpxor", "vrcpps", "vrcpss",
				"vroundpd", "vroundps", "vroundsd", "vroundss", "vrsqrtps", "vrsqrtss", "vshufpd", "vshufps", "vsqrtpd",
				"vsqrtps", "vsqrtsd", "vsqrtss", "vstmxcsr", "vsubpd", "vsubps", "vsubsd", "vsubss", "vtestpd",
				"vtestps", "vucomisd", "vucomiss", "vunpckhpd", "vunpckhps", "vunpcklpd", "vunpcklps", "vxorpd",
				"vxorps", "vzeroall", "vzeroupper", "xabort", "xbegin", "xend", "xtest", "vmgetinfo", "vmsetinfo",
				"vmdxdsbl", "vmdxenbl", "vmcpuid", "vmhlt", "vmsplaf", "vmpushfd", "vmpopfd", "vmcli", "vmsti",
				"vmiretd", "vmsgdt", "vmsidt", "vmsldt", "vmstr", "vmsdte", "vpcext", "vfmaddsubps", "vfmaddsubpd",
				"vfmsubaddps", "vfmsubaddpd", "vfmaddps", "vfmaddpd", "vfmaddss", "vfmaddsd", "vfmsubps", "vfmsubpd",
				"vfmsubss", "vfmsubsd", "vfnmaddps", "vfnmaddpd", "vfnmaddss", "vfnmaddsd", "vfnmsubps", "vfnmsubpd",
				"vfnmsubss", "vfnmsubsd").stream().map(opt -> new Operation(opt.toUpperCase()))
				.collect(Collectors.toCollection(ArrayList::new));

		ar.operationJmps = Arrays
				.asList("JE", "JNE", "JG", "JGE", "JL", "JLE", "JA", "JAE", "JB", "JBE", "JNB", "JO", "JNO", "JC",
						"JNC", "JS", "JNS", "JZ", "JNZ", "CALL", "JMP", "JCXZ", "JP", "JECXZ", "JNP", "JPO", "RET",
						"RETN")
				.stream().map(opt -> new Operation(opt)).collect(Collectors.toCollection(ArrayList::new));

		ar.registers = Arrays
				.asList("AH", "BH", "CH", "DH", "AL", "BL", "CL", "DL", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B",
						"R14B", "R15B")
				.stream().map(op -> new ArchitectureRepresentation.Register(op, "GEN", 8))
				.collect(Collectors.toCollection(ArrayList::new));

		Arrays.asList("AX", "BX", "CX", "DX", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W").stream()
				.map(op -> new Register(op, "GEN", 16)).forEach(ar.registers::add);

		Arrays.asList("EAX", "EBX", "ECX", "EDX", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D").stream()
				.map(op -> new Register(op, "GEN", 32)).forEach(ar.registers::add);

		Arrays.asList("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13",
				"R14", "R15", "MM0", "MM1", "MM2", "MM3", "MM4", "MM5", "MM6", "MM7").stream()
				.map(op -> new Register(op, "GEN", 64)).forEach(ar.registers::add);

		Arrays.asList("XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7").stream()
				.map(op -> new Register(op, "GEN", 128)).forEach(ar.registers::add);

		Arrays.asList("CS", "DS", "ES", "FS", "GS", "SS").stream().map(op -> new Register(op, "SEG", 16))
				.forEach(ar.registers::add);

		Arrays.asList("EDI", "DI", "ESI", "SI").stream().map(op -> new Register(op, "IND", 16))
				.forEach(ar.registers::add);

		Arrays.asList("EBP", "BP", "ESP", "SP", "EIP", "IP").stream().map(op -> new Register(op, "PTR", 16))
				.forEach(ar.registers::add);

		Arrays.asList("CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF", "IOPL", "NT", "RF", "VM", "AC", "VIF",
				"VIP", "ID").stream().map(op -> new Register(op, "FLG", 1)).forEach(ar.registers::add);

		ar.lengthKeywords = new ArrayList<>();
		ar.lengthKeywords.add(new LengthKeyWord("BYTE", 8));
		ar.lengthKeywords.add(new LengthKeyWord("WORD", 16));
		ar.lengthKeywords.add(new LengthKeyWord("DWORD", 32));
		ar.lengthKeywords.add(new LengthKeyWord("QWORD", 64));
		ar.lengthKeywords.add(new LengthKeyWord("XMMWORD", 128));

		// ar.constantVariableRegex = "(^(0x|0X)[0-9A-Fa-f]+$)|" // hex starts
		// // with 0x
		// + "([0-9A-Fa-f]+(h|H)$)|" // hex ends with h
		// + "(^[0-9]+$)|" // positive integer
		// + "(^[0-9]+.[0-9]+$)|" // positive float
		// + "(^-[0-9]+$)|" // negative integer
		// + "(^-[0-9]+.[0-9]+$)|" // negative float
		// + "(^[0-8]+(Q|q)$)|" // octal
		// + "(^[0-1]+(B|b)$)";
		ar.constantVariableRegex = "([0-9A-Fa-f]{3,10}(h|H)$)";

		ar.memoryVariableRegex = "(^DS:)|(^ds:)|([\\s\\S]*\\[[\\s\\S]+\\])";

		// address operation operand1, operrand2; comments
		ar.lineFormats = new ArrayList<>(Arrays.asList(new LineFormat(
				"(?<OPT>[\\S]+)[\\s]+(?<OPN1>[\\S\\s]+)[\\s]*,[\\s]*(?<OPN2>[\\S\\s]+),[\\s]*(?<OPN3>[\\S\\s]+)", 3),
				new LineFormat("(?<OPT>[\\S]+)[\\s]+(?<OPN1>[\\S\\s]+)[\\s]*,[\\s]*(?<OPN2>[\\S\\s]+)", 2), //
				new LineFormat("(?<OPT>[\\S]+)[\\s]+(?<OPN1>[\\S\\s]+)", 1), //
				new LineFormat("(?<OPT>[\\S]+)[\\s]+", 0)));

		ar.processor = "metapc";
		ar.jmpKeywords = new ArrayList<>(Arrays.asList("large", "short", "far"));

		return ar;
	}

	public static void main(String[] args) throws Exception {
		ArchitectureRepresentation ar = ArchitectureRepresentationMetaPC.get();
		Lines.flushToFile(Lines.from(ar.toXml()),
				KamResourceLoader.writeFile("architectures/" + ar.processor + ".xml").getAbsolutePath());
		//
		// AsmLineNormalizationResource.init(ar);
		//
		// FeatureConstructor constructor = new
		// FeatureConstructor(NormalizationLevel.NORM_TYPE,
		// FreqFeatures.getFeatureMemFreq(),
		// FreqFeatures.getFeatureMemGramFreq(2),
		// FreqFeatures.getFeatureMemOprFreq());
		//
		// constructor.featureElements.forEach(System.out::println);
		// AsmLineNormalizationUtils.init(ar, false);

		// BinarySurrogate bs = BinarySurrogate.load(new File(
		// "C:\\test\\tmp\\admin\\zlib-1.2.7.dll.tmp"));
		// List<Function> funcs = bs.toFunctions();
		//
		// funcs.get(0).blocks.stream().flatMap(blk -> blk.codes.stream())
		// .forEach(System.out::println);
		//
		// AsmLineNormalizer.tokenizeAsmFragments(funcs.get(0),
		// NormalizationLevel.NORM_TYPE_LENGTH).forEach(
		// frag -> frag.asmLines.forEach(ln -> System.out
		// .println(StringResources.JOINER_DASH.join(ln))));

	}
}
