package ca.mcgill.sis.dmas.kam1n0.impl.disassembly;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;

public class RawRegisterList {

	public static Set<String> REG_METAPC = Arrays
			.asList("rep", "rax", "rbp", "rbx", "rsp", "rdx", "rsi", "rdi", "rcx", "eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", 
					"esp", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
					"r15",  
					"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d",
					"r15d", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w",
					"r15w",
					"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "spl", "bpl", "sil", "dil", "ip", "es", "cs",
					"ss", "ds", "fs", "gs", "cf", "zf", "sf", "of", "pf", "af", "tf", "if", "df", "efl", "st0", "st1",
					"st2", "st3", "st4", "st5", "st6", "st7", "fpctrl", "fpstat", "fptags", "mm0", "mm1", "mm2", "mm3",
					"mm4", "mm5", "mm6", "mm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
					"xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "mxcsr", "ymm0", "ymm1", "ymm2",
					"ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14",
					"ymm15", "bnd0", "bnd1", "bnd2", "bnd3", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21",
					"xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31", "ymm16",
					"ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27",
					"ymm28", "ymm29", "ymm30", "ymm31", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
					"zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18",
					"zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29",
					"zmm30", "zmm31", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7")
			.stream().map(str -> str.toLowerCase()).collect(Collectors.toSet());

	public static Set<String> REG_ARM = Arrays
			.asList("R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC",
					"CPSR", "CPSR_flg", "SPSR", "SPSR_flg", "T", "CS", "DS", "acc0", "FPSID", "FPSCR", "FPEXC",
					"FPINST", "FPINST2", "MVFR0", "MVFR1", "APSR", "IAPSR", "EAPSR", "XPSR", "IPSR", "EPSR", "IEPSR",
					"MSP", "PSP", "PRIMASK", "BASEPRI", "BASEPRI_MAX", "FAULTMASK", "CONTROL", "Q0", "Q1", "Q2", "Q3",
					"Q4", "Q5", "Q6", "Q7", "Q8", "Q9", "Q10", "Q11", "Q12", "Q13", "Q14", "Q15", "D0", "D1", "D2",
					"D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10", "D11", "D12", "D13", "D14", "D15", "D16", "D17",
					"D18", "D19", "D20", "D21", "D22", "D23", "D24", "D25", "D26", "D27", "D28", "D29", "D30", "D31",
					"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14",
					"S15", "S16", "S17", "S18", "S19", "S20", "S21", "S22", "S23", "S24", "S25", "S26", "S27", "S28",
					"S29", "S30", "S31", "CF", "ZF", "NF", "VF", "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8",
					"X9", "X10", "X11", "X12", "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22",
					"X23", "X24", "X25", "X26", "X27", "X28", "X29", "X30", "XZR", "SP", "PC", "V0", "V1", "V2", "V3",
					"V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11", "V12", "V13", "V14", "V15", "V16", "V17", "V18",
					"V19", "V20", "V21", "V22", "V23", "V24", "V25", "V26", "V27", "V28", "V29", "V30", "V31")
			.stream().map(str -> str.toLowerCase()).collect(Collectors.toSet());

	public static Set<String> REG_PPC = Arrays.asList("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
			"r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",
			"r26", "r27", "r28", "r29", "r30", "r31", "vle", "cs", "ds", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
			"f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22",
			"f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31", "sr0", "sr1", "sr2", "sr3", "sr4", "sr5",
			"sr6", "sr7", "sr8", "sr9", "sr10", "sr11", "sr12", "sr13", "sr14", "sr15", "cr", "fpscr", "msr", "vscr",
			"vrsave", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
			"v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29",
			"v30", "v31", "v32", "v33", "v34", "v35", "v36", "v37", "v38", "v39", "v40", "v41", "v42", "v43", "v44",
			"v45", "v46", "v47", "v48", "v49", "v50", "v51", "v52", "v53", "v54", "v55", "v56", "v57", "v58", "v59",
			"v60", "v61", "v62", "v63", "v64", "v65", "v66", "v67", "v68", "v69", "v70", "v71", "v72", "v73", "v74",
			"v75", "v76", "v77", "v78", "v79", "v80", "v81", "v82", "v83", "v84", "v85", "v86", "v87", "v88", "v89",
			"v90", "v91", "v92", "v93", "v94", "v95", "v96", "v97", "v98", "v99", "v100", "v101", "v102", "v103",
			"v104", "v105", "v106", "v107", "v108", "v109", "v110", "v111", "v112", "v113", "v114", "v115", "v116",
			"v117", "v118", "v119", "v120", "v121", "v122", "v123", "v124", "v125", "v126", "v127", "vs0", "vs1", "vs2",
			"vs3", "vs4", "vs5", "vs6", "vs7", "vs8", "vs9", "vs10", "vs11", "vs12", "vs13", "vs14", "vs15", "vs16",
			"vs17", "vs18", "vs19", "vs20", "vs21", "vs22", "vs23", "vs24", "vs25", "vs26", "vs27", "vs28", "vs29",
			"vs30", "vs31", "vs32", "vs33", "vs34", "vs35", "vs36", "vs37", "vs38", "vs39", "vs40", "vs41", "vs42",
			"vs43", "vs44", "vs45", "vs46", "vs47", "vs48", "vs49", "vs50", "vs51", "vs52", "vs53", "vs54", "vs55",
			"vs56", "vs57", "vs58", "vs59", "vs60", "vs61", "vs62", "vs63").stream().map(str -> str.toLowerCase())
			.collect(Collectors.toSet());

	public static Set<String> REG_MIPST = Arrays.asList("$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0",
			"$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
			"$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra", "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6",
			"$f7", "$f8", "$f9", "$f10", "$f11", "$f12", "$f13", "$f14", "$f15", "$f16", "$f17", "$f18", "$f19", "$f20",
			"$f21", "$f22", "$f23", "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31", "pc", "cs", "ds",
			"mips16").stream().map(str -> str.toLowerCase()).collect(Collectors.toSet());

	public static Set<String> get(ArchitectureType type) {
		switch (type.archName) {
		case "metapc":
			return REG_METAPC;
		case "arm":
			return REG_ARM;
		case "ppc":
			return REG_PPC;
		case "mips":
			return REG_MIPST;
		default:
			return null;
		}
	}

}
