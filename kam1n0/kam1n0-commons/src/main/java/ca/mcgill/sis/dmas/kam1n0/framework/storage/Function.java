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

import java.io.Serializable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBytes;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedPrimary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;

public class Function implements Serializable, Iterable<Block> {

	private static Logger logger = LoggerFactory.getLogger(Function.class);
	private static final long serialVersionUID = 2087261362680018344L;

	@KeyedSecondary
	public long functionId = -1;

	public long srcId = -1;

	public String srcName = StringResources.STR_EMPTY;

	public String functionName = StringResources.STR_EMPTY;

	@AsBytes
	public List<Long> callingFunctionIds;

	@AsBytes
	public List<String> ccalls;

	public long binaryId;

	public String binaryName = StringResources.STR_EMPTY;

	public long numBlocks;
	
	public long codeSize;

	@AsBytes
	public Set<Long> blockIds;

	public transient List<Block> blocks;

	public transient List<Comment> comments;

	public long startingAddress;

	@AsString
	public Architecture architecture;

	public void fill(long uid, AsmObjectFactory factory) {
		if (blocks == null)
			blocks = factory.obj_blocks.queryMultiple(uid, "blockId", blockIds).collect();
	}

	public void fillComments(long uid, AsmObjectFactory factory) {
		if (comments == null)
			comments = factory.obj_comments.queryMultiple(uid, functionId).collect();
	}

	@Override
	public Iterator<Block> iterator() {
		if (blocks == null) {
			logger.error("This class has unfilled attribute functions. "
					+ "It looks like it is retrieved from a database. "
					+ "You need to call this.retrieveBlocks(ObjectFactory factory) " + "before accessing blocks.");
			return null;
		}
		return blocks.iterator();
	}

	public String getBinaryName() {
		return binaryName;
	}

	public void setBinaryName(String binaryName) {
		this.binaryName = binaryName;
	}

	public String getSrcName() {
		return srcName;
	}

	public void setSrcName(String srcName) {
		this.srcName = srcName;
	}

	public transient Object tempObject;

}
