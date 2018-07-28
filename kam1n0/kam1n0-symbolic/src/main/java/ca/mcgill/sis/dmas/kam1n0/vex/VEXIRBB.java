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
package ca.mcgill.sis.dmas.kam1n0.vex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.sun.org.apache.bcel.internal.generic.I2F;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.LogicGraph;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexJumpKind;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmExit;
import ca.mcgill.sis.dmas.kam1n0.vex.statements.StmIMark;

public class VEXIRBB {

	private static Logger logger = LoggerFactory.getLogger(VEXIRBB.class);

	public VexArchitecture architecture;

	public String binaryName;
	public String functionName;
	public String blockName;
	public long blockId;
	public long functionId;

	public ArrayList<VexVariableType> types = new ArrayList<>();

	public ArrayList<VexStatement> statements = new ArrayList<>();

	public int offsetsIP;

	public VexJumpKind jmpKind;

	public VexExpression next;

	public void print() {
		try {
			System.out.println((new ObjectMapper()).writerWithDefaultPrettyPrinter().writeValueAsString(this));
		} catch (Exception e) {
		}
	}

	public VEXIRBB() {
	}

	private native void translateToVexIR(//
			int arch, //
			int hwcaps, //
			int endness, //
			int ppc_icache_line_szB, //
			int ppc_dcbz_szB, //
			int ppc_dczl_szB, //
			int arm64_dMinLin_lg2_szB, //
			int arm64_iMinLine_lg2_szB, //
			int hwcache_info_num_levels, //
			int hwcache_info_num_caches, //
			int hwcache_info_caches, //
			boolean hwcache_info_icaches_maintain_choherence, //
			int info_x86_cr0, //
			byte[] bytes, long address, int num_ins);

	public static synchronized EntryPair<List<VEXIRBB>, ListMultimap<Long, Long>> translate(
			VexArchitecture architecture, long address, byte[] bytes) {

		if (bytes == null || bytes.length < 2) {
			VEXIRBB empty = new VEXIRBB();
			empty.architecture = architecture;
			empty.jmpKind = null;
			empty.next = null;
			empty.offsetsIP = -1;
			return new EntryPair<>(Arrays.asList(empty), ArrayListMultimap.create());
		}

		List<VEXIRBB> bbs = new ArrayList<>();
		ListMultimap<Long, Long> callMap = ArrayListMultimap.create();
		VEXIRBB current = null;
		int byteUsed = 0;
		long nAddr = address;
		do {

			VEXIRBB ins = new VEXIRBB(architecture, nAddr, 1, Arrays.copyOfRange(bytes, byteUsed, bytes.length));
			if (current == null)
				current = ins;
			else {
				// merge:
				int tmp_offset = current.types.size();
				ins.statements.forEach(stm -> stm.updateTmpOffset(tmp_offset));
				current.types.addAll(ins.types);
				current.statements.addAll(ins.statements);
				current.jmpKind = ins.jmpKind;
				current.next = ins.next;
			}

			Optional<VexStatement> conditionalBranchPoint = ins.statements.stream().filter(
					stm -> stm.tag == VexStatementType.Ist_Exit && ((StmExit) stm).jumpKind == VexJumpKind.Ijk_Boring)
					.findAny();

			if (conditionalBranchPoint.isPresent()) {
				bbs.add(current);
				long addr = current.getStartingAddr();
				long nextSeq = current.getSequentialNextAddr();
				long nextBranch = ((StmExit) conditionalBranchPoint.get()).dst.getVal();
				callMap.put(addr, nextSeq);
				callMap.put(addr, nextBranch);

				StmIMark currentMark = null;
				for (VexStatement stm : current.statements) {
					if (stm.tag.equals(VexStatementType.Ist_IMark)) {
						StmIMark mark = (StmIMark) stm;
						mark.ina = mark.addr_unsigned;
						currentMark = mark;
					}
					if (currentMark != null)
						stm.ina = currentMark.addr_unsigned;
				}

				current = null;
			}

			nAddr = ins.getSequentialNextAddr();
			byteUsed += ins.getLength();

			if (byteUsed >= bytes.length)
				break;
		} while (true);

		return new EntryPair<>(bbs, callMap);
	}

	public static synchronized VEXIRBB translate(VexArchitecture architecture, long address, int num_ins, byte[] bytes,
			HashMap<Long, String> dat) {

		if (bytes == null || bytes.length < 2 || num_ins < 1) {
			VEXIRBB empty = new VEXIRBB();
			empty.architecture = architecture;
			empty.jmpKind = null;
			empty.next = null;
			empty.offsetsIP = -1;
			return empty;
		}

		VEXIRBB first = null;

		if (architecture.type.equals(VexArchitectureType.VexArchMIPS32)) {
			num_ins = num_ins > (bytes.length * 8 / 32) ? num_ins : (bytes.length * 8 / 32);
		}

		first = new VEXIRBB(architecture, address, num_ins > 99 ? 99 : num_ins, bytes);
		int byteUsed = first.getLength();
		long nAddr = first.getSequentialNextAddr();
		int num_ins_left = num_ins - first.getImarkCount();
		int byte_left = bytes.length - byteUsed;

		// System.out.println(num_ins_left + "/" + num_ins);
		while (byteUsed < bytes.length && num_ins_left > 0) {

			VEXIRBB tmp = new VEXIRBB(architecture, nAddr, num_ins_left > 99 ? 99 : num_ins_left,
					Arrays.copyOfRange(bytes, byteUsed, bytes.length));
			if (tmp.getLength() == 0)
				break;
			byteUsed += tmp.getLength();
			num_ins_left = num_ins_left - tmp.getImarkCount();
			nAddr = tmp.getSequentialNextAddr();
			byte_left = bytes.length - byteUsed;

			// System.out.println(num_ins_left + "/" + num_ins);

			// merge:
			int tmp_offset = first.types.size();
			tmp.statements.forEach(stm -> stm.updateTmpOffset(tmp_offset));
			first.types.addAll(tmp.types);
			first.statements.addAll(tmp.statements);
			first.jmpKind = tmp.jmpKind;
			first.next = tmp.next;
			// first.offsetsIP remains the same.
		}
		// System.out.println(first.statements.size());

		// translating the resting bytes:
		while (byte_left > 0) {
			// System.out.println(byte_left + " bytes left...");
			// one-by-one translation.
			VEXIRBB tmp = new VEXIRBB(architecture, nAddr, 1, Arrays.copyOfRange(bytes, byteUsed, bytes.length));
			if (tmp.getLength() == 0)
				break;
			byteUsed += tmp.getLength();
			nAddr = tmp.getSequentialNextAddr();
			byte_left = bytes.length - byteUsed;

			// merge:
			int tmp_offset = first.types.size();
			tmp.statements.forEach(stm -> stm.updateTmpOffset(tmp_offset));
			first.types.addAll(tmp.types);
			first.statements.addAll(tmp.statements);
			first.jmpKind = tmp.jmpKind;
			first.next = tmp.next;
		}

		// System.out.println(dat);
		StmIMark currentMark = null;
		for (VexStatement stm : first.statements) {
			if (stm.tag.equals(VexStatementType.Ist_IMark)) {
				StmIMark mark = (StmIMark) stm;
				mark.ina = mark.addr_unsigned;
				if (dat.containsKey(mark.addr_unsigned)) {
					mark.dat = dat.get(mark.addr_unsigned);
				}
				currentMark = mark;
				// System.out.println(mark.addr_unsigned);
				// System.out.println(mark.dat);
			}
			if (currentMark != null)
				stm.ina = currentMark.addr_unsigned;
		}

		return first;
	}

	public static VEXIRBB translateBlk(Block blk) {
		try {
			VEXIRBB vex = VEXIRBB.translate(VexArchitecture.convert(blk.architecture), blk.sea, blk.codes.size(),
					blk.bytes, blk.dat);
			vex.blockId = blk.blockId;
			vex.blockName = blk.blockName;
			vex.functionId = blk.functionId;
			vex.functionName = blk.functionName;
			vex.binaryName = blk.binaryName;
			return vex;
		} catch (Exception e) {
			logger.error("Failed to translate to vex code for blk " + blk.blockName + ": " + blk.getAsmLines()
					+ "; bytes: " + blk.bytes, e);
			return null;
		}
	}

	@JsonIgnore
	public int getLength() {
		return statements.stream().filter(st -> st.tag.equals(VexStatementType.Ist_IMark))
				.mapToInt(st -> ((StmIMark) st).len_unsigned).sum();
	}

	@JsonIgnore
	public int getImarkCount() {
		return (int) statements.stream().filter(st -> st.tag.equals(VexStatementType.Ist_IMark)).count();
	}

	@JsonIgnore
	public long getStartingAddr() {
		Optional<VexStatement> firstImark = statements.stream().filter(st -> st.tag.equals(VexStatementType.Ist_IMark))
				.findFirst();
		if (firstImark.isPresent()) {
			StmIMark mark = ((StmIMark) firstImark.get());
			long addr = mark.addr_unsigned;
			if (architecture.type == VexArchitectureType.VexArchARM) {
				addr += mark.delta_unsigned;
			}
			return addr;
		} else
			return -1;
	}

	@JsonIgnore
	public Long getSequentialNextAddr() {
		for (int i = statements.size() - 1; i >= 0; i--) {
			if (statements.get(i).tag.equals(VexStatementType.Ist_IMark)) {
				long addr = ((StmIMark) statements.get(i)).addr_unsigned + ((StmIMark) statements.get(i)).len_unsigned;
				if (architecture.type == VexArchitectureType.VexArchARM) {
					addr += ((StmIMark) statements.get(i)).delta_unsigned;
				}
				return addr;
			}
		}
		return null;
	}

	private VEXIRBB(VexArchitecture architecture, long address, int num_ins, byte[] bytes) {
		this.architecture = architecture;

		this.translateToVexIR(//
				VexEnumeration.retrieveIndex(architecture.type, VexArchitectureType.class), //
				architecture.info.hwcaps, //
				VexEnumeration.retrieveIndex(architecture.info.endness, VexEndnessType.class),
				architecture.info.ppc_icache_line_szB, //
				architecture.info.ppc_dcbz_szB, //
				architecture.info.ppc_dcbzl_szB, //
				architecture.info.arm64_dMinLine_lg2_szB, //
				architecture.info.arm64_iMinLine_lg2_szB, //
				architecture.info.cacheInfo.num_levels, //
				architecture.info.cacheInfo.num_caches, //
				0, //
				architecture.info.cacheInfo.icaches_maintain_coherence, //
				0xffffffff, //
				bytes, address, num_ins);
	}

	public ComputationGraph translate() {
		return ComputationGraph.translate(this);
	}

	public List<List<String>> toVexStrs(boolean simplify) {

		HashMap<Long, VexToStrState> ins_states = new HashMap<>();
		Function<Long, VexToStrState> supplier = addr -> {
			if (ins_states.containsKey(addr))
				return ins_states.get(addr);
			VexToStrState state = new VexToStrState(architecture, simplify);
			ins_states.put(addr, state);
			return state;
		};
		List<List<String>> ls = new ArrayList<>();
		boolean firstImark = true;
		for (VexStatement stm : this.statements)
			if (stm.tag != VexStatementType.Ist_NoOp) {
				if (stm.tag == VexStatementType.Ist_IMark) {
					if (firstImark) {
						firstImark = false;
						VexToStrState state = supplier.apply(stm.ina);
						String stmStr = stm.toStr(state);
						ls.add(Arrays.asList("0x" + Long.toHexString(stm.ina), stmStr));
					}
				} else {
					VexToStrState state = supplier.apply(stm.ina);
					String stmStr = stm.toStr(state);
					if (stmStr.length() > 0)
						ls.add(Arrays.asList("0x" + Long.toHexString(stm.ina), stmStr));
				}
			}
		return ls;
	}

	public static void main(String[] args) throws Exception {

		VexEnumeration.activate();

		VexArchitecture arch = new VexArchitecture();
		arch.type = VexArchitectureType.VexArchAMD64;
		arch.info.endness = VexEndnessType.VexEndnessLE;

		VEXIRBB vexirbb = new VEXIRBB(arch, 0x400400, 5,
				new byte[] { (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90 });

		ObjectMapper mapper = new ObjectMapper();
		String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(vexirbb);
		System.out.print(json);
	}

}
