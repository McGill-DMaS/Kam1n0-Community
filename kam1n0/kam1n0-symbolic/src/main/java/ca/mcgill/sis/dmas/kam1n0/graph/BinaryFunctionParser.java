package ca.mcgill.sis.dmas.kam1n0.graph;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ListMultimap;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BlockSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.vex.VEXIRBB;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;

public class BinaryFunctionParser {

	private static Logger logger = LoggerFactory.getLogger(BinaryFunctionParser.class);

	public static Binary fromBinary(byte[] bytes, String functionName, String binaryName, long addr,
			Architecture arch) {

		EntryPair<List<VEXIRBB>, ListMultimap<Long, Long>> entry = VEXIRBB.translate(VexArchitecture.convert(arch),
				addr, bytes);

		BinarySurrogate binary = new BinarySurrogate();
		binary.architecture = arch;
		binary.name = binaryName;

		FunctionSurrogate func = new FunctionSurrogate();
		func.name = functionName;
		func.sea = addr;
		func.see = addr + bytes.length * 8;
		func.srcid = -1;

		binary.functions.add(func);

		List<VEXIRBB> vexirbbs = entry.key;
		List<LogicGraph> graphs = new ArrayList<>();
		ListMultimap<Long, Long> callMap = entry.value;

		HashMap<Long, VEXIRBB> map = new HashMap<>();
		for (VEXIRBB bb : vexirbbs) {
			BlockSurrogate bs = new BlockSurrogate();
			graphs.add(bb.translate().simplify());
			bs.sea = bb.getStartingAddr();
			bs.eea = bs.sea + bb.getLength();
			bs.name = "loc_" + bb.getStartingAddr();
			bs.id = bs.sea;
			List<Long> callees = callMap.get(bs.sea);
			bs.call.addAll(callees);
			bs.src.addAll(bb.toVexStrs(true));
			func.blocks.add(bs);
			map.put(bs.sea, bb);
		}

		binary.processRawBinarySurrogate();

		Binary nb = binary.toBinary();
		nb.functions.parallelStream().forEach(f -> {
			f.blocks = f.blocks.stream().map(blk -> {
				VEXIRBB bb = map.get(blk.sea);
				return new BlockLogicWrapper(blk, bb.toVexStrs(true), bb.translate().simplify());
			}).collect(Collectors.toList());
		});

		return nb;
	}

	public List<LogicGraph> translate(BinarySurrogate binary, Predicate<BlockSurrogate> blkf) {
		return binary.functions.stream().flatMap(func -> func.blocks.stream().map(blk -> {
			if (blkf.test(blk)) {
				// System.out.println(blk.name);
				// System.out.flush();
				VEXIRBB vex = translate(VexArchitecture.convert(binary.architecture), blk, binary.name, func.name);
				vex.blockId = blk.id;
				vex.blockName = blk.name;
				vex.functionId = func.id;
				vex.functionName = func.name;
				vex.binaryName = binary.name;
				ComputationGraph g = vex.translate();
				return g.simplify();
			}
			return null;
		})).filter(g -> g != null).collect(Collectors.toList());
	}

	private VEXIRBB translate(VexArchitecture arch, BlockSurrogate blk, String binaryName, String functionName) {
		try {
			VEXIRBB bb = VEXIRBB.translate(arch, blk.sea, blk.src.size(), StringResources.converteByteString(blk.bytes),
					blk.dat);
			return bb;
		} catch (Exception e) {
			logger.error("Failed to translate to vex code for blk " + blk.name + ": " + blk.asmLines() + "; bytes: "
					+ blk.bytes, e);
			return null;
		}
	}

}
