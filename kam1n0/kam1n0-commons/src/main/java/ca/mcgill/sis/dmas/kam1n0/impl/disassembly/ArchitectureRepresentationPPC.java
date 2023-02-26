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
		
		ar.operations.add(new Operation("efsabs"));
		ar.operations.add(new Operation("efsadd"));
		ar.operations.add(new Operation("efscfsf"));
		ar.operations.add(new Operation("efscfsi"));
		ar.operations.add(new Operation("efscfuf"));
		ar.operations.add(new Operation("efscfui"));
		ar.operations.add(new Operation("efscmpeq"));
		ar.operations.add(new Operation("efscmpgt"));
		ar.operations.add(new Operation("efscmplt"));
		ar.operations.add(new Operation("efsctsf"));
		ar.operations.add(new Operation("efsctsi"));
		ar.operations.add(new Operation("efsctsiz"));
		ar.operations.add(new Operation("efsctuf"));
		ar.operations.add(new Operation("efsctui"));
		ar.operations.add(new Operation("efsctuiz"));
		ar.operations.add(new Operation("efsdiv"));
		ar.operations.add(new Operation("efsmul"));
		ar.operations.add(new Operation("efsnabs"));
		ar.operations.add(new Operation("efsneg"));
		ar.operations.add(new Operation("efssub"));
		ar.operations.add(new Operation("efststeq"));
		ar.operations.add(new Operation("efststgt"));
		ar.operations.add(new Operation("efststlt"));
		ar.operations.add(new Operation("evabs"));
		ar.operations.add(new Operation("evaddiw"));
		ar.operations.add(new Operation("evaddsmiaaw"));
		ar.operations.add(new Operation("evaddssiaaw"));
		ar.operations.add(new Operation("evaddumiaaw"));
		ar.operations.add(new Operation("evaddusiaaw"));
		ar.operations.add(new Operation("evaddw"));
		ar.operations.add(new Operation("evand"));
		ar.operations.add(new Operation("evandc"));
		ar.operations.add(new Operation("evcmpeq"));
		ar.operations.add(new Operation("evcmpgts"));
		ar.operations.add(new Operation("evcmpgtu"));
		ar.operations.add(new Operation("evcmplts"));
		ar.operations.add(new Operation("evcmpltu"));
		ar.operations.add(new Operation("evcntlsw"));
		ar.operations.add(new Operation("evcntlzw"));
		ar.operations.add(new Operation("evdivws"));
		ar.operations.add(new Operation("evdivwu"));
		ar.operations.add(new Operation("eveqv"));
		ar.operations.add(new Operation("evextsb"));
		ar.operations.add(new Operation("evextsh"));
		ar.operations.add(new Operation("evfsabs"));
		ar.operations.add(new Operation("evfsabs"));
		ar.operations.add(new Operation("evfsadd"));
		ar.operations.add(new Operation("evfsadd"));
		ar.operations.add(new Operation("evfscfsf"));
		ar.operations.add(new Operation("evfscfsf"));
		ar.operations.add(new Operation("evfscfsi"));
		ar.operations.add(new Operation("evfscfsi"));
		ar.operations.add(new Operation("evfscfuf"));
		ar.operations.add(new Operation("evfscfuf"));
		ar.operations.add(new Operation("evfscfui"));
		ar.operations.add(new Operation("evfscfui"));
		ar.operations.add(new Operation("evfscmpeq"));
		ar.operations.add(new Operation("evfscmpeq"));
		ar.operations.add(new Operation("evfscmpgt"));
		ar.operations.add(new Operation("evfscmpgt"));
		ar.operations.add(new Operation("evfscmplt"));
		ar.operations.add(new Operation("evfscmplt"));
		ar.operations.add(new Operation("evfsctsf"));
		ar.operations.add(new Operation("evfsctsf"));
		ar.operations.add(new Operation("evfsctsi"));
		ar.operations.add(new Operation("evfsctsi"));
		ar.operations.add(new Operation("evfsctsiz"));
		ar.operations.add(new Operation("evfsctsiz"));
		ar.operations.add(new Operation("evfsctuf"));
		ar.operations.add(new Operation("evfsctuf"));
		ar.operations.add(new Operation("evfsctui"));
		ar.operations.add(new Operation("evfsctui"));
		ar.operations.add(new Operation("evfsctuiz"));
		ar.operations.add(new Operation("evfsctuiz"));
		ar.operations.add(new Operation("evfsdiv"));
		ar.operations.add(new Operation("evfsdiv"));
		ar.operations.add(new Operation("evfsmul"));
		ar.operations.add(new Operation("evfsmul"));
		ar.operations.add(new Operation("evfsnabs"));
		ar.operations.add(new Operation("evfsnabs"));
		ar.operations.add(new Operation("evfsneg"));
		ar.operations.add(new Operation("evfsneg"));
		ar.operations.add(new Operation("evfssub"));
		ar.operations.add(new Operation("evfssub"));
		ar.operations.add(new Operation("evfststeq"));
		ar.operations.add(new Operation("evfststeq"));
		ar.operations.add(new Operation("evfststgt"));
		ar.operations.add(new Operation("evfststgt"));
		ar.operations.add(new Operation("evfststlt"));
		ar.operations.add(new Operation("evfststlt"));
		ar.operations.add(new Operation("evldd"));
		ar.operations.add(new Operation("evlddx"));
		ar.operations.add(new Operation("evldh"));
		ar.operations.add(new Operation("evldhx"));
		ar.operations.add(new Operation("evldw"));
		ar.operations.add(new Operation("evldwx"));
		ar.operations.add(new Operation("evlhhesplat"));
		ar.operations.add(new Operation("evlhhesplatx"));
		ar.operations.add(new Operation("evlhhossplat"));
		ar.operations.add(new Operation("evlhhossplatx"));
		ar.operations.add(new Operation("evlhhousplat"));
		ar.operations.add(new Operation("evlhhousplatx"));
		ar.operations.add(new Operation("evlwhe"));
		ar.operations.add(new Operation("evlwhex"));
		ar.operations.add(new Operation("evlwhos"));
		ar.operations.add(new Operation("evlwhosx"));
		ar.operations.add(new Operation("evlwhou"));
		ar.operations.add(new Operation("evlwhoux"));
		ar.operations.add(new Operation("evlwhsplat"));
		ar.operations.add(new Operation("evlwhsplatx"));
		ar.operations.add(new Operation("evlwwsplat"));
		ar.operations.add(new Operation("evlwwsplatx"));
		ar.operations.add(new Operation("evmergehi"));
		ar.operations.add(new Operation("evmergehilo"));
		ar.operations.add(new Operation("evmergelo"));
		ar.operations.add(new Operation("evmergelohi"));
		ar.operations.add(new Operation("evmhegsmfaa"));
		ar.operations.add(new Operation("evmhegsmfan"));
		ar.operations.add(new Operation("evmhegsmiaa"));
		ar.operations.add(new Operation("accumulate"));
		ar.operations.add(new Operation("evmhegsmian"));
		ar.operations.add(new Operation("evmhegumiaa"));
		ar.operations.add(new Operation("evmhegumian"));
		ar.operations.add(new Operation("evmhesmf"));
		ar.operations.add(new Operation("evmhesmfa"));
		ar.operations.add(new Operation("evmhesmfaaw"));
		ar.operations.add(new Operation("evmhesmfanw"));
		ar.operations.add(new Operation("evmhesmi"));
		ar.operations.add(new Operation("evmhesmia"));
		ar.operations.add(new Operation("evmhesmiaaw"));
		ar.operations.add(new Operation("evmhesmianw"));
		ar.operations.add(new Operation("evmhessf"));
		ar.operations.add(new Operation("evmhessfa"));
		ar.operations.add(new Operation("evmhessfaaw"));
		ar.operations.add(new Operation("evmhessfanw"));
		ar.operations.add(new Operation("evmhessiaaw"));
		ar.operations.add(new Operation("evmhessianw"));
		ar.operations.add(new Operation("evmheumi"));
		ar.operations.add(new Operation("evmheumia"));
		ar.operations.add(new Operation("evmheumiaaw"));
		ar.operations.add(new Operation("evmheumianw"));
		ar.operations.add(new Operation("evmheusiaaw"));
		ar.operations.add(new Operation("evmheusianw"));
		ar.operations.add(new Operation("evmhogsmfaa"));
		ar.operations.add(new Operation("evmhogsmfan"));
		ar.operations.add(new Operation("evmhogsmiaa"));
		ar.operations.add(new Operation("evmhogsmian"));
		ar.operations.add(new Operation("evmhogumiaa"));
		ar.operations.add(new Operation("evmhogumian"));
		ar.operations.add(new Operation("evmhosmf"));
		ar.operations.add(new Operation("evmhosmfa"));
		ar.operations.add(new Operation("evmhosmfaaw"));
		ar.operations.add(new Operation("evmhosmfanw"));
		ar.operations.add(new Operation("evmhosmi"));
		ar.operations.add(new Operation("evmhosmia"));
		ar.operations.add(new Operation("evmhosmiaaw"));
		ar.operations.add(new Operation("evmhosmianw"));
		ar.operations.add(new Operation("evmhossf"));
		ar.operations.add(new Operation("evmhossfa"));
		ar.operations.add(new Operation("evmhossfaaw"));
		ar.operations.add(new Operation("evmhossfanw"));
		ar.operations.add(new Operation("evmhossiaaw"));
		ar.operations.add(new Operation("evmhossianw"));
		ar.operations.add(new Operation("evmhoumi"));
		ar.operations.add(new Operation("evmhoumia"));
		ar.operations.add(new Operation("evmhoumiaaw"));
		ar.operations.add(new Operation("evmhoumianw"));
		ar.operations.add(new Operation("evmhousiaaw"));
		ar.operations.add(new Operation("evmhousianw"));
		ar.operations.add(new Operation("evmra"));
		ar.operations.add(new Operation("evmwhsmf"));
		ar.operations.add(new Operation("evmwhsmfa"));
		ar.operations.add(new Operation("evmwhsmi"));
		ar.operations.add(new Operation("evmwhsmia"));
		ar.operations.add(new Operation("evmwhssf"));
		ar.operations.add(new Operation("evmwhssfa"));
		ar.operations.add(new Operation("evmwhumi"));
		ar.operations.add(new Operation("evmwhumia"));
		ar.operations.add(new Operation("evmwlsmi"));
		ar.operations.add(new Operation("evmwlsmiaaw"));
		ar.operations.add(new Operation("evmwlsmianw"));
		ar.operations.add(new Operation("evmwlssiaaw"));
		ar.operations.add(new Operation("words"));
		ar.operations.add(new Operation("evmwlssianw"));
		ar.operations.add(new Operation("evmwlumia"));
		ar.operations.add(new Operation("evmwlumiaaw"));
		ar.operations.add(new Operation("words"));
		ar.operations.add(new Operation("evmwlumianw"));
		ar.operations.add(new Operation("evmwlusiaaw"));
		ar.operations.add(new Operation("evmwlusianw"));
		ar.operations.add(new Operation("evmwsmf"));
		ar.operations.add(new Operation("evmwsmfa"));
		ar.operations.add(new Operation("evmwsmfaa"));
		ar.operations.add(new Operation("evmwsmfan"));
		ar.operations.add(new Operation("evmwsmi"));
		ar.operations.add(new Operation("evmwsmia"));
		ar.operations.add(new Operation("evmwsmiaa"));
		ar.operations.add(new Operation("evmwsmian"));
		ar.operations.add(new Operation("evmwssf"));
		ar.operations.add(new Operation("evmwssfa"));
		ar.operations.add(new Operation("evmwssfaa"));
		ar.operations.add(new Operation("evmwssfan"));
		ar.operations.add(new Operation("evmwumi"));
		ar.operations.add(new Operation("evmwumia"));
		ar.operations.add(new Operation("evmwumiaa"));
		ar.operations.add(new Operation("evmwumian"));
		ar.operations.add(new Operation("evnand"));
		ar.operations.add(new Operation("evneg"));
		ar.operations.add(new Operation("evnor"));
		ar.operations.add(new Operation("evor"));
		ar.operations.add(new Operation("evorc"));
		ar.operations.add(new Operation("evrlw"));
		ar.operations.add(new Operation("evrlwi"));
		ar.operations.add(new Operation("evrndw"));
		ar.operations.add(new Operation("evsel"));
		ar.operations.add(new Operation("evslw"));
		ar.operations.add(new Operation("evslwi"));
		ar.operations.add(new Operation("evsplatfi"));
		ar.operations.add(new Operation("evsplati"));
		ar.operations.add(new Operation("evsrwis"));
		ar.operations.add(new Operation("evsrwiu"));
		ar.operations.add(new Operation("evsrws"));
		ar.operations.add(new Operation("evsrwu"));
		ar.operations.add(new Operation("evstdd"));
		ar.operations.add(new Operation("evstddx"));
		ar.operations.add(new Operation("evstdh"));
		ar.operations.add(new Operation("evstdhx"));
		ar.operations.add(new Operation("evstdw"));
		ar.operations.add(new Operation("evstdwx"));
		ar.operations.add(new Operation("evstwhe"));
		ar.operations.add(new Operation("evstwhex"));
		ar.operations.add(new Operation("evstwho"));
		ar.operations.add(new Operation("evstwhox"));
		ar.operations.add(new Operation("evstwwe"));
		ar.operations.add(new Operation("evstwwex"));
		ar.operations.add(new Operation("evstwwo"));
		ar.operations.add(new Operation("evstwwox"));
		ar.operations.add(new Operation("evsubfsmiaaw"));
		ar.operations.add(new Operation("evsubfssiaaw"));
		ar.operations.add(new Operation("evsubfumiaaw"));
		ar.operations.add(new Operation("evsubfusiaaw"));
		ar.operations.add(new Operation("evsubfw"));
		ar.operations.add(new Operation("evsubifw"));
		ar.operations.add(new Operation("evxor"));
		ar.operations.add(new Operation("extsb"));
		ar.operations.add(new Operation("exts"));
		ar.operations.add(new Operation("extsh"));
		ar.operations.add(new Operation("exts"));
		ar.operations.add(new Operation("e_add16i"));
		ar.operations.add(new Operation("e_add2"));
		ar.operations.add(new Operation("e_add2is"));
		ar.operations.add(new Operation("e_addi"));
		ar.operations.add(new Operation("e_add"));
		ar.operations.add(new Operation("e_addic"));
		ar.operations.add(new Operation("e_addi"));
		ar.operations.add(new Operation("e_and2"));
		ar.operations.add(new Operation("e_and2i"));
		ar.operations.add(new Operation("e_andi"));
		ar.operations.add(new Operation("e_and"));
		ar.operations.add(new Operation("e_b"));
		ar.operations.add(new Operation("e_bc"));
		ar.operations.add(new Operation("e_bcl"));
		ar.operations.add(new Operation("e_bl"));
		ar.operations.add(new Operation("e_cmp16i"));
		ar.operations.add(new Operation("e_cmph"));
		ar.operations.add(new Operation("e_cmph16i"));
		ar.operations.add(new Operation("e_cmphl"));
		ar.operations.add(new Operation("e_cmphl16i"));
		ar.operations.add(new Operation("e_cmpi"));
		ar.operations.add(new Operation("e_cmpl16i"));
		ar.operations.add(new Operation("e_cmpli"));
		ar.operations.add(new Operation("e_crand"));
		ar.operations.add(new Operation("e_crandc"));
		ar.operations.add(new Operation("e_creqv"));
		ar.operations.add(new Operation("e_crnand"));
		ar.operations.add(new Operation("e_crnor"));
		ar.operations.add(new Operation("e_cror"));
		ar.operations.add(new Operation("e_crorc"));
		ar.operations.add(new Operation("e_crxor"));
		ar.operations.add(new Operation("e_lbz"));
		ar.operations.add(new Operation("e_lbzu"));
		ar.operations.add(new Operation("e_lha"));
		ar.operations.add(new Operation("e_lhau"));
		ar.operations.add(new Operation("e_lhz"));
		ar.operations.add(new Operation("e_lhzu"));
		ar.operations.add(new Operation("e_li"));
		ar.operations.add(new Operation("e_lis"));
		ar.operations.add(new Operation("e_lmw"));
		ar.operations.add(new Operation("e_lwz"));
		ar.operations.add(new Operation("e_lwzu"));
		ar.operations.add(new Operation("e_mcrf"));
		ar.operations.add(new Operation("e_mull2i"));
		ar.operations.add(new Operation("e_mulli"));
		ar.operations.add(new Operation("e_or2i"));
		ar.operations.add(new Operation("e_or2is"));
		ar.operations.add(new Operation("e_ori"));
		ar.operations.add(new Operation("e_or"));
		ar.operations.add(new Operation("e_rlw"));
		ar.operations.add(new Operation("e_rl"));
		ar.operations.add(new Operation("e_rlwi"));
		ar.operations.add(new Operation("e_rlw"));
		ar.operations.add(new Operation("e_rlwimi"));
		ar.operations.add(new Operation("e_rlwinm"));
		ar.operations.add(new Operation("e_slwi"));
		ar.operations.add(new Operation("e_slw"));
		ar.operations.add(new Operation("e_srwi"));
		ar.operations.add(new Operation("e_srw"));
		ar.operations.add(new Operation("e_stb"));
		ar.operations.add(new Operation("e_stbu"));
		ar.operations.add(new Operation("e_sth"));
		ar.operations.add(new Operation("e_sthu"));
		ar.operations.add(new Operation("e_stmw"));
		ar.operations.add(new Operation("e_stw"));
		ar.operations.add(new Operation("e_stwu"));
		ar.operations.add(new Operation("e_subfic"));
		ar.operations.add(new Operation("e_subfi"));
		ar.operations.add(new Operation("e_xori"));
		ar.operations.add(new Operation("e_xor"));
		ar.operations.add(new Operation("icbi"));
		ar.operations.add(new Operation("icblc"));
		ar.operations.add(new Operation("icbt"));
		ar.operations.add(new Operation("icbtls"));
		ar.operations.add(new Operation("isel"));
		ar.operations.add(new Operation("isync"));
		ar.operations.add(new Operation("lbz"));
		ar.operations.add(new Operation("lbzu"));
		ar.operations.add(new Operation("lbzux"));
		ar.operations.add(new Operation("lbzx"));
		ar.operations.add(new Operation("lha"));
		ar.operations.add(new Operation("lhau"));
		ar.operations.add(new Operation("lhaux"));
		ar.operations.add(new Operation("lhax"));
		ar.operations.add(new Operation("lhbrx"));
		ar.operations.add(new Operation("lhz"));
		ar.operations.add(new Operation("lhzu"));
		ar.operations.add(new Operation("lhzux"));
		ar.operations.add(new Operation("lhzx"));
		ar.operations.add(new Operation("lmw"));
		ar.operations.add(new Operation("lwarx"));
		ar.operations.add(new Operation("lwbrx"));
		ar.operations.add(new Operation("lwz"));
		ar.operations.add(new Operation("lwzu"));
		ar.operations.add(new Operation("lwzux"));
		ar.operations.add(new Operation("lwzx"));
		ar.operations.add(new Operation("mba"));
		ar.operations.add(new Operation("mcrf"));
		ar.operations.add(new Operation("mcrxr"));
		ar.operations.add(new Operation("mfcr"));
		ar.operations.add(new Operation("mfdc"));
		ar.operations.add(new Operation("mfdcrx4"));
		ar.operations.add(new Operation("mfmsr"));
		ar.operations.add(new Operation("mfspr"));
		ar.operations.add(new Operation("msync3"));
		ar.operations.add(new Operation("mtcrf"));
		ar.operations.add(new Operation("mtdcr4"));
		ar.operations.add(new Operation("mtdcrx4"));
		ar.operations.add(new Operation("mtmsr"));
		ar.operations.add(new Operation("mtspr"));
		ar.operations.add(new Operation("se_add"));
		ar.operations.add(new Operation("se_addi"));
		ar.operations.add(new Operation("se_and"));
		ar.operations.add(new Operation("se_an"));
		ar.operations.add(new Operation("se_andc"));
		ar.operations.add(new Operation("se_andi"));
		ar.operations.add(new Operation("se_b"));
		ar.operations.add(new Operation("se_bc"));
		ar.operations.add(new Operation("se_bclri"));
		ar.operations.add(new Operation("se_bctr"));
		ar.operations.add(new Operation("se_bctrl"));
		ar.operations.add(new Operation("se_bgeni"));
		ar.operations.add(new Operation("se_bl"));
		ar.operations.add(new Operation("se_blr"));
		ar.operations.add(new Operation("se_blrl"));
		ar.operations.add(new Operation("se_bmaski"));
		ar.operations.add(new Operation("se_bseti"));
		ar.operations.add(new Operation("se_btsti"));
		ar.operations.add(new Operation("se_cmp"));
		ar.operations.add(new Operation("se_cmph"));
		ar.operations.add(new Operation("se_cmphl"));
		ar.operations.add(new Operation("se_cmpi"));
		ar.operations.add(new Operation("se_cmpl"));
		ar.operations.add(new Operation("se_cmpli"));
		ar.operations.add(new Operation("se_extsb"));
		ar.operations.add(new Operation("se_extsh"));
		ar.operations.add(new Operation("se_extzb"));
		ar.operations.add(new Operation("se_extzh"));
		ar.operations.add(new Operation("se_illegal"));
		ar.operations.add(new Operation("se_isync"));
		ar.operations.add(new Operation("se_lbz"));
		ar.operations.add(new Operation("se_lhz"));
		ar.operations.add(new Operation("se_li"));
		ar.operations.add(new Operation("se_lwz"));
		ar.operations.add(new Operation("se_mfar"));
		ar.operations.add(new Operation("se_mfctr"));
		ar.operations.add(new Operation("se_mflr"));
		ar.operations.add(new Operation("se_mr"));
		ar.operations.add(new Operation("se_mtar"));
		ar.operations.add(new Operation("se_mtctr"));
		ar.operations.add(new Operation("se_mtlr"));
		ar.operations.add(new Operation("se_mullw"));
		ar.operations.add(new Operation("se_neg"));
		ar.operations.add(new Operation("se_not"));
		ar.operations.add(new Operation("se_or"));
		ar.operations.add(new Operation("se_rfci"));
		ar.operations.add(new Operation("se_rfdi"));
		ar.operations.add(new Operation("se_rfi"));
		ar.operations.add(new Operation("se_sc"));
		ar.operations.add(new Operation("se_slw"));
		ar.operations.add(new Operation("se_slwi"));
		ar.operations.add(new Operation("se_sraw"));
		ar.operations.add(new Operation("se_srawi"));
		ar.operations.add(new Operation("se_srw"));
		ar.operations.add(new Operation("se_srwi"));
		ar.operations.add(new Operation("se_stb"));
		ar.operations.add(new Operation("se_sth"));
		ar.operations.add(new Operation("se_stw"));
		ar.operations.add(new Operation("se_sub"));
		ar.operations.add(new Operation("se_subf"));
		ar.operations.add(new Operation("se_subi"));
		ar.operations.add(new Operation("se_sub"));
		

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
