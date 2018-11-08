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
package ca.mcgill.sis.dmas.kam1n0.app.adata;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.io.collection.heap.Ranker;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;

public class FunctionDataUnit implements Serializable {

	private static final long serialVersionUID = 5704957213270193920L;
	public String binaryName;
	public String binaryId;
	public String functionName;
	public String functionId;
	public String startAddress;
	public int blockSize;
	public SrcFunction srcFunc;

	public ArrayList<BlockDataUnit> nodes = new ArrayList<>();
	public ArrayList<Link> links = new ArrayList<>();
	public int codeSize;

	public static class Link implements Serializable {
		private static final long serialVersionUID = -3012737921524201819L;
		public String source, target;
		public double value;

		public Link(String src, String tar, double val) {
			source = src;
			target = tar;
			value = val;
		}

		public Link() {
		}

	}

	public FunctionDataUnit() {
	}

	public FunctionDataUnit shadowClone() {
		FunctionDataUnit data = new FunctionDataUnit();
		data.binaryId = this.binaryId;
		data.binaryName = this.binaryName;
		data.functionId = this.functionId;
		data.functionName = this.functionName;
		data.startAddress = this.startAddress;
		data.blockSize = this.blockSize;
		return data;
	}

	public void sort() {
		Ranker<BlockDataUnit> heap = new Ranker<>();
		for (BlockDataUnit node : nodes) {
			if (node.srcCodes != null && node.srcCodes.size() > 0) {
				try {
					String addrStr = AsmLineNormalizer.tokenizeAsmLineBySpace(node.srcCodes.get(0)).get(0);
					Long addr = Long.parseLong(addrStr.replaceAll("^0x", ""), 16);
					heap.push(addr, node);
				} catch (Exception e) {
					heap.push(Long.parseLong(node.blockID), node);
				}
			} else {
				heap.push(Long.parseLong(node.blockID), node);
			}
		}

		this.nodes = heap.sortedList(true);

	}

	public FunctionDataUnit(String binaryName, String binaryId, String functionName, String functionId,
			String startAddress) {
		this.binaryName = binaryName;
		this.binaryId = binaryId;
		this.functionName = functionName;
		this.functionId = functionId;
		this.startAddress = startAddress;
		this.blockSize = 0;
	}

	public FunctionDataUnit(Function function) {
		this(function, false);
	}

	public FunctionDataUnit(Function function, boolean metaOnly) {
		this(function, null, metaOnly);
	}

	public FunctionDataUnit(Function function, AsmLineNormalizer normalizer, boolean metaOnly) {

		HashSet<Long> validBlkIds = new HashSet<>();

		if (!metaOnly) {
			for (Block block : function) {

				AsmFragment fragment = block;
				if (normalizer != null)
					fragment = normalizer.tokenizeAsmFragment(block);

				BlockDataUnit node = new BlockDataUnit();
				List<String> fline = block.peek();
				if (fline != null && fline.size() > 1)
					node.name = fline.get(0);
				node.blockID = Long.toString(block.blockId);
				node.sea = Long.toString(block.sea);
				node.srcCodes = fragment.getAsmLines().stream().map(AsmLineNormalizer::formatCodeLine)
						.collect(Collectors.toList());
				if (node.srcCodes.size() < 1)
					node.srcCodes.add("0x" + Long.toHexString(block.blockId) + " [Kam1n0: EMPTY]");
				node.name = block.blockName;
				node.functionId = Long.toString(function.functionId);
				nodes.add(node);
				validBlkIds.add(block.blockId);
				node.appAttr = block.fillWebAttr();
			}

			for (Block block : function) {
				for (long target : block.callingBlocks) {
					if (validBlkIds.contains(block.blockId) && validBlkIds.contains(target))
						links.add(new Link(Long.toString(block.blockId), Long.toString(target), 1.0));
				}
			}

		}
		this.binaryId = Long.toString(function.binaryId);
		this.binaryName = function.binaryName;
		this.functionId = Long.toString(function.functionId);
		this.functionName = function.functionName;
		this.startAddress = Long.toString(function.startingAddress);
		this.blockSize = (int) function.numBlocks;
		this.codeSize = (int) function.codeSize;
	}

}
