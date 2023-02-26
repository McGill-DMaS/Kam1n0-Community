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
package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBasic;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBytes;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.Ignored;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedPrimary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;

public class Block implements AsmFragment, Serializable {

	private static final long serialVersionUID = -1077415849569673075L;
	private static ObjectMapper mapper = new ObjectMapper();

	@KeyedSecondary
//	@ObjectFactoryMultiTenancy.KeyedPrimaryPartial(bytes=1)
//	@KeyedPrimary
	public long blockId = -1;

	@AsString
	public List<Long> callingBlocks;

	/**
	 * Definition of 'peer' is application/model-specific. By default it is the number of blocks in the function the
	 * block belongs to, but this can also be the number of instructions in some or all blocks of that function.
	 * Since this data can be persisted, the same application/model be used to create the data and to process it.
	 */
	public int peerSize;

	public long functionId;

	public String functionName = StringResources.STR_EMPTY;

	public long binaryId;

	public String binaryName = StringResources.STR_EMPTY;

	public String blockName = StringResources.STR_EMPTY;

	public long codesSize = -1;
	
	public long funcCodeSize = -1;

	@AsBytes
	public List<List<String>> codes;
	
	@AsBytes
	public List<List<Integer>> oprTypes;

	public long sea = -1;

	public byte[] bytes = null;

	@AsBytes
	public HashMap<Long, String> dat;

	@AsString
	public Architecture architecture;

	public String mergeCode() {
		try {
			return mapper.writeValueAsString(this.codes);
		} catch (JsonProcessingException e) {
			return null;
		}
	}

	public void loadCode(String content) {
		try {
			this.codes = mapper.readValue(content, new TypeReference<List<List<String>>>() {
			});
		} catch (IOException e) {

		}
	}

	public String formatCode() {
		return StringResources.JOINER_LINE.join(Iterables.transform(codes, AsmLineNormalizer::formatCodeLine));
	}

	@Override
	public Iterator<List<String>> iterator() {
		return codes.iterator();
	}

	@Override
	public List<List<String>> getAsmLines() {
		return codes;
	}

	public List<String> peek() {
		if (codes == null || codes.isEmpty())
			return AsmLineNormalizer.emptyList;
		else
			return codes.get(0);
	}

	@Override
	public boolean equals(Object obj) {
		Block blk = (Block) obj;
		if (blk == null)
			return false;
		else
			return this.blockId == blk.blockId;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(this.blockId);
	}

	@Override
	public String toString() {
		return StringResources.JOINER_TOKEN_CSV_SPACE.join(blockName, functionName, blockId);
	}

	public Block(Block blk) {
		super();
		this.blockId = blk.blockId;
		this.callingBlocks = blk.callingBlocks;
		this.peerSize = blk.peerSize;
		this.functionId = blk.functionId;
		this.functionName = blk.functionName;
		this.binaryId = blk.binaryId;
		this.binaryName = blk.binaryName;
		this.blockName = blk.blockName;
		this.codes = blk.codes;
		this.sea = blk.sea;
		this.bytes = blk.bytes;
		this.dat = blk.dat;
		this.architecture = blk.architecture;
		this.codesSize = blk.codesSize;
	}

	public Block() {
	}

	// An application can override this method to push data to the web client
	// Currently sym1n0 uses it to push additional information to the web about the
	// block.
	// A wrapper implementation need another structure to hold block-specific
	// information.
	// but in this case, it is with default FunctionDataUnit, so can be used in
	// existing JS UI functions.
	// Saw ca.mcgill.sis.dmas.kam1n0.graph.BlockLogicWrapper
	// and
	// ca.mcgill.sis.dmas.kam1n0.app.clone.symbolic.Sym1n0ApplicationMeta.getFunction
	// for sample usage.
	// In the web you can directly do:
	// func[0].node[0].your_added_attribute.
	public Map<String, Object> fillWebAttr() {
		return new HashMap<>();
	}

	@Override
	public List<List<Integer>> getOprTypes() {
		return this.oprTypes;
	}

}
