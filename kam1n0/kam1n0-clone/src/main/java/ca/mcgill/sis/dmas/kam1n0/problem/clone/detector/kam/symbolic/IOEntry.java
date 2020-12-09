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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import com.fasterxml.jackson.annotation.JsonCreator;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;

public class IOEntry {
	public Long functionId;
	public Long blockId;
	public String varName;
	public List<Long> calls;
	public int funcSize;

	@JsonCreator
	public IOEntry() {

	}

	public IOEntry(Block blk, String varName) {
		this.functionId = blk.functionId;
		this.blockId = blk.blockId;
		this.varName = varName;
		this.calls = blk.callingBlocks;

		// Note: blk.peerSize is by default the number of basic block in the function, but in theory could also be
		// something else like an instruction count. This depend on the caller. See peerSize definition.
		this.funcSize = blk.peerSize;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof IOEntry))
			return false;
		IOEntry ent = (IOEntry) obj;
		return this.functionId.equals(ent.functionId) && this.blockId.equals(ent.blockId)
				&& this.varName.equals(ent.varName);
	}

	@Override
	public int hashCode() {
		return (new HashCodeBuilder()).append(functionId).append(blockId).append(varName).build();
	}

}
