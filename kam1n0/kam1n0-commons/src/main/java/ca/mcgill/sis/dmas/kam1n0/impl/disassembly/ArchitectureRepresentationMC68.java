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

public class ArchitectureRepresentationMC68 {

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

		ar.addOperation("abcd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("sbcd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("add", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "a", "a.b", "a.d", "a.l", "a.p", "a.s",
				"a.w", "a.x", "i", "i.b", "i.d", "i.l", "i.p", "i.s", "i.w", "i.x", "q", "q.b", "q.d", "q.l", "q.p",
				"q.s", "q.w", "q.x", "x", "x.b", "x.d", "x.l", "x.p", "x.s", "x.w", "x.x");
		ar.addOperation("and", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "i", "i.b", "i.d", "i.l", "i.p", "i.s",
				"i.w", "i.x");
		ar.addOperation("as", "l", "l.b", "l.d", "l.l", "l.p", "l.s", "l.w", "l.x", "r", "r.b", "r.d", "r.l", "r.p",
				"r.s", "r.w", "r.x");

		ar.addOperation("bchg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bfchg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("b[f]chg", "bchg", "bfchg");

		ar.addOperation("bclr", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bfclr", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("b[f]clr", "bclr", "bfclr");

		ar.addOperation("bset", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bfset", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("bset_bfset", "bset", "bfset");

		ar.addOperation("btst", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bftst", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("b[f]tst", "btst", "bftst");

		ar.addOperation("bitrev", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("byterev", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("bit/byte_rev", "bitrev", "byterev");

		ar.addOperation("bfext", "s", "s.b", "s.d", "s.l", "s.p", "s.s", "s.w", "s.x", "u", "u.b", "u.d", "u.l", "u.p",
				"u.s", "u.w", "u.x");

		ar.addOperation("bfffo", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bfins", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bgnd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bkpt", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("cas", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "2", "2.b", "2.d", "2.l", "2.p", "2.s",
				"2.w", "2.x");
		ar.addOperation("chk", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "2", "2.b", "2.d", "2.l", "2.p", "2.s",
				"2.w", "2.x");
		ar.addOperation("cin", "v", "v.b", "v.d", "v.l", "v.p", "v.s", "v.w", "v.x");
		ar.addOperation("clr", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("cmp", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "2", "2.b", "2.d", "2.l", "2.p", "2.s",
				"2.w", "2.x", "a", "a.b", "a.d", "a.l", "a.p", "a.s", "a.w", "a.x", "i", "i.b", "i.d", "i.l", "i.p",
				"i.s", "i.w", "i.x", "m", "m.b", "m.d", "m.l", "m.p", "m.s", "m.w", "m.x");
		ar.addOperation("cpush", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("div", "s", "s.b", "s.d", "s.l", "s.p", "s.s", "s.w", "s.x", "sl", "sl.b", "sl.d", "sl.l",
				"sl.p", "sl.s", "sl.w", "sl.x", "u", "u.b", "u.d", "u.l", "u.p", "u.s", "u.w", "u.x", "ul", "ul.b",
				"ul.d", "ul.l", "ul.p", "ul.s", "ul.w", "ul.x");
		ar.addOperation("eor", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "i", "i.b", "i.d", "i.l", "i.p", "i.s",
				"i.w", "i.x");
		ar.addOperation("exg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("exi");
		ar.addOperation("ext", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "b", "b.b", "b.d", "b.l", "b.p", "b.s",
				"b.w", "b.x");

		ar.addOperation("fabs", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fdabs", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsabs", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s]abs", "fabs", "fdabs", "fsabs");

		ar.addOperation("facos", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fcos", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "h", "h.b", "h.d", "h.l", "h.p", "h.s",
				"h.w", "h.x");
		ar.addOprGroup("f[a]cos", "facos", "fcos");

		ar.addOperation("fadd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fdadd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsadd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s]fadd", "fadd", "fdadd", "fsadd");

		ar.addOperation("fasin", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsin", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "h", "h.b", "h.d", "h.l", "h.p", "h.s",
				"h.w", "h.x");
		ar.addOprGroup("f[a]sin", "fsin", "fasin");

		ar.addOperation("fssub", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsub", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fdsub", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s]sub", "fssub", "fsub", "fdsub");

		ar.addOperation("fatan", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "h", "h.b", "h.d", "h.l", "h.p", "h.s",
				"h.w", "h.x");
		ar.addOperation("ftan", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "h", "h.b", "h.d", "h.l", "h.p", "h.s",
				"h.w", "h.x");
		ar.addOprGroup("f[a]tan", "fatan", "ftan");

		ar.addOperation("fsincos");
		ar.addOperation("ftentox", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fcmp", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("ftst", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");

		ar.addOperation("fddiv", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fdiv", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsdiv");
		ar.addOperation("fsgldiv", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s/sgl]div", "fddiv", "fdiv", "fsgldiv", "fsdiv");

		ar.addOperation("fdmove", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fmove", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "cr", "cr.b", "cr.d", "cr.l", "cr.p",
				"cr.s", "cr.w", "cr.x", "m", "m.b", "m.d", "m.l", "m.p", "m.s", "m.w", "m.x");
		ar.addOperation("fsmove", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s]move", "fdmove", "fmove", "fsmove");

		ar.addOperation("fdmul", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fmul", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsglmul", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsmul", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s/sgl]mul", "fdmul", "fmul", "fsglmul", "fsmul");

		ar.addOperation("fdneg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fneg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsneg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s]neg", "fdneg", "fneg", "fsneg");

		ar.addOperation("fsqrt", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fssqrt", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fdsqrt", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOprGroup("f[d/s]sqrt", "fsqrt", "fssqrt", "fdsqrt");

		ar.addOperation("flog2", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("flog10", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("flogn", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "p1", "p1.b", "p1.d", "p1.l", "p1.p",
				"p1.s", "p1.w", "p1.x");
		ar.addOperation("fmod", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fnop", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("nop", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("frem", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("frestore", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fs", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "cale", "cale.b", "cale.d", "cale.l",
				"cale.p", "cale.s", "cale.w", "cale.x");
		ar.addOperation("ftrap", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("ftwotox", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fsave");

		ar.addOperation("fetox", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "m1", "m1.b", "m1.d", "m1.l", "m1.p",
				"m1.s", "m1.w", "m1.x");
		ar.addOperation("ff1", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fgetexp", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fgetman", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("fint", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "rz", "rz.b", "rz.d", "rz.l", "rz.p",
				"rz.s", "rz.w", "rz.x");
		ar.addOperation("halt", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("illegal", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("intouch", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("move", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "16", "16.b", "16.d", "16.l", "16.p",
				"16.s", "16.w", "16.x", "a", "a.b", "a.d", "a.l", "a.p", "a.s", "a.w", "a.x", "c", "c.b", "c.d", "c.l",
				"c.p", "c.s", "c.w", "c.x", "m", "m.b", "m.d", "m.l", "m.p", "m.s", "m.w", "m.x", "p", "p.b", "p.d",
				"p.l", "p.p", "p.s", "p.w", "p.x", "q", "q.b", "q.d", "q.l", "q.p", "q.s", "q.w", "q.x", "s", "s.b",
				"s.d", "s.l", "s.p", "s.s", "s.w", "s.x");
		ar.addOperation("mv", "s", "s.b", "s.d", "s.l", "s.p", "s.s", "s.w", "s.x", "z", "z.b", "z.d", "z.l", "z.p",
				"z.s", "z.w", "z.x");
		ar.addOperation("mov", "3q", "3q.b", "3q.d", "3q.l", "3q.p", "3q.s", "3q.w", "3q.x", "clr", "clr.b", "clr.d",
				"clr.l", "clr.p", "clr.s", "clr.w", "clr.x");
		ar.addOperation("pmov", "e", "e.b", "e.d", "e.l", "e.p", "e.s", "e.w", "e.x");
		ar.addOperation("ms", "aac", "aac.b", "aac.d", "aac.l", "aac.p", "aac.s", "aac.w", "aac.x", "ac", "ac.b",
				"ac.d", "ac.l", "ac.p", "ac.s", "ac.w", "ac.x", "acl", "acl.b", "acl.d", "acl.l", "acl.p", "acl.s",
				"acl.w", "acl.x", "sac", "sac.b", "sac.d", "sac.l", "sac.p", "sac.s", "sac.w", "sac.x");
		ar.addOperation("masac", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("maaac", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("mac", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "l", "l.b", "l.d", "l.l", "l.p", "l.s",
				"l.w", "l.x");
		ar.addOperation("mul", "s", "s.b", "s.d", "s.l", "s.p", "s.s", "s.w", "s.x", "u", "u.b", "u.d", "u.l", "u.p",
				"u.s", "u.w", "u.x");
		ar.addOperation("nbcd", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("lea", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("link", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("lpstop", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("ls", "l", "l.b", "l.d", "l.l", "l.p", "l.s", "l.w", "l.x", "r", "r.b", "r.d", "r.l", "r.p",
				"r.s", "r.w", "r.x");
		ar.addOperation("neg", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "x", "x.b", "x.d", "x.l", "x.p", "x.s",
				"x.w", "x.x");
		ar.addOperation("not", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("or", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "i", "i.b", "i.d", "i.l", "i.p", "i.s",
				"i.w", "i.x");
		ar.addOperation("pack", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("ptest", "r", "r.b", "r.d", "r.l", "r.p", "r.s", "r.w", "r.x", "w", "w.b", "w.d", "w.l", "w.p",
				"w.s", "w.w", "w.x");
		ar.addOperation("ptrap", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("trap", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "v", "v.b", "v.d", "v.l", "v.p", "v.s",
				"v.w", "v.x");
		ar.addOperation("pulse", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("pvalid", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("remsl", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("remul", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("reset", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("sub", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "a", "a.b", "a.d", "a.l", "a.p", "a.s",
				"a.w", "a.x", "i", "i.b", "i.d", "i.l", "i.p", "i.s", "i.w", "i.x", "q", "q.b", "q.d", "q.l", "q.p",
				"q.s", "q.w", "q.x", "x", "x.b", "x.d", "x.l", "x.p", "x.s", "x.w", "x.x");
		ar.addOperation("swap", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("tas", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("tbl", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("tst", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("unlk", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("unpk", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("wddata", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("wdebug", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("pea", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("pflush", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "r", "r.b", "r.d", "r.l", "r.p", "r.s",
				"r.w", "r.x");
		ar.addOperation("pload", "r", "r.b", "r.d", "r.l", "r.p", "r.s", "r.w", "r.x", "w", "w.b", "w.d", "w.l", "w.p",
				"w.s", "w.w", "w.x");
		ar.addOperation("prestore", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("ps", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x", "ave", "ave.b", "ave.d", "ave.l", "ave.p",
				"ave.s", "ave.w", "ave.x");
		ar.addOperation("ror", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("rol", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("roxl", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("roxr", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("stop", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("sats", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("bra", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addOperation("s", "", ".b", ".d", ".l", ".p", ".", ".w", ".x");

		// branching
		ar.addJmpOperation("bsr");
		ar.addJmpOperation("call", "m");
		ar.addJmpOperation("b", "", ".", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("bcc");
		ar.addJmpOperation("fbcc");
		ar.addJmpOperation("fb", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("db", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("dbcc");
		ar.addJmpOperation("fdb", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("fdbcc");
		ar.addJmpOperation("scc");
		ar.addJmpOperation("fscc");
		ar.addJmpOperation("jsr", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("jmp", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("rt", "d", "d.b", "d.d", "d.l", "d.p", "d.s", "d.w", "d.x", "e", "e.b", "e.d", "e.l", "e.p",
				"e.s", "e.w", "e.x", "m", "m.b", "m.d", "m.l", "m.p", "m.s", "m.w", "m.x", "r", "r.b", "r.d", "r.l",
				"r.p", "r.s", "r.w", "r.x", "s", "s.b", "s.d", "s.l", "s.p", "s.s", "s.w", "s.x");
		ar.addJmpOperation("pdb", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");
		ar.addJmpOperation("pb", "", ".b", ".d", ".l", ".p", ".s", ".w", ".x");

		// end of operations

		// general purpose 32b data register
		Arrays.asList("d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7").stream().map(idt -> new Register(idt, "GEN", 32))
				.forEach(reg -> ar.registers.add(reg));

		// general purpose 32b address register
		Arrays.asList("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7").stream().map(idt -> new Register(idt, "ADR", 32))
				.forEach(reg -> ar.registers.add(reg));

		// general purpose 80b floating point register
		Arrays.asList("fp0", "fp1", "fp2", "fp3", "fp4", "fp5", "fp6", "fp7").stream()
				.map(idt -> new Register(idt, "FLT", 80)).forEach(reg -> ar.registers.add(reg));

		// Breakpoint Acknowledge Data AND Breakpoint Acknowledge Control (16bit)
		// see https://opensource.apple.com/source/gdb/gdb-413/src/include/opcode/m68k.h
		Arrays.asList("bad0", "bad1", "bad2", "bad3", "bad4", "bad5", "bad6", "bad7", "bac0", "bac1", "bac2", "bac3",
				"bac4", "bac5", "bac6", "bac7").stream().map(idt -> new Register(idt, "BAX", 16))
				.forEach(reg -> ar.registers.add(reg));

		// stack pointer neutralized in different modes
		Arrays.asList("usp", "sp", "msp", "isp").stream().map(idt -> new Register(idt, "STP", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Alternate Function Code Registers (SFC and DFC)
		Arrays.asList("sfc", "dfc").stream().map(idt -> new Register(idt, "AFCR", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Cache-related Cache Address Register & Cache Control Register
		Arrays.asList("caar", "cacr").stream().map(idt -> new Register(idt, "CAH", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Transparent Related Register
		Arrays.asList("tc", "itt0", "itt1", "dtt0", "dtt1", "tt0", "tt1").stream()
				.map(idt -> new Register(idt, "TRN", 32)).forEach(reg -> ar.registers.add(reg));

		// Pointer registers
		Arrays.asList("urp", "srp", "drp", "crp").stream().map(idt -> new Register(idt, "TRN", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Access level registers
		Arrays.asList("cal", "val").stream().map(idt -> new Register(idt, "LVL", 32))
				.forEach(reg -> ar.registers.add(reg));

		// Other control related register
		Arrays.asList("acc0", "acc1", "ac", "scc", "pcsr", "acusr", "accext01", "accext23").stream()
				.map(idt -> new Register(idt, "CTL", 32)).forEach(reg -> ar.registers.add(reg));

		ar.registers.add(new Register("fpcr", "fpcr", 16));
		ar.registers.add(new Register("fpsr", "fpsr", 32));
		ar.registers.add(new Register("fpiar", "fpiar", 32));
		ar.registers.add(new Register("pc", "pc", 32));
		ar.registers.add(new Register("ccr", "ccr", 8));
		ar.registers.add(new Register("sr", "sr", 5));
		ar.registers.add(new Register("mmusr", "mmusr", 32));
		ar.registers.add(new Register("vbr", "vbr", 32));
		ar.registers.add(new Register("macsr", "macsr", 32));
		ar.registers.add(new Register("mask", "mask", 32));
		ar.registers.add(new Register("cs", "cs", 32));
		ar.registers.add(new Register("ds", "ds", 32));

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

		ar.processor = "mc68";
		ar.jmpKeywords = new ArrayList<>();
		return ar;
	}

	public static void main(String[] args) throws Exception {
		ArchitectureRepresentation ar = ArchitectureRepresentationMC68.get();
		Lines.flushToFile(Lines.from(ar.toXml()),
				KamResourceLoader.writeFile("architectures/" + ar.processor + ".xml").getAbsolutePath());
		AsmLineNormalizer normalizer = new AsmLineNormalizer(new NormalizationSetting(),
				ArchitectureType.mc68.retrieveNormalizationResource());
		System.out.println(normalizer.tokenizeAsmLine(Arrays.asList("", "fddiv.l", "d0", "a0")));

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
