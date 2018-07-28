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
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;

public class Binary implements Serializable, Iterable<Function>, Cloneable {

	private static Logger logger = LoggerFactory.getLogger(Binary.class);
	private static final long serialVersionUID = 9071539724574724923L;

	public String binaryName = StringResources.STR_EMPTY;

	@KeyedSecondary
	public long binaryId = -1;

	public long numFunctions = 0;

	public Set<Long> functionIds;

	@AsString
	public Architecture architecture;

	public transient List<Function> functions;

	public List<Function> retrieveFunctions() {
		return functions;
	}

	public void fill(long uid, AsmObjectFactory factory) {
		if (functions == null) {
			functions = factory.obj_functions.queryMultiple(uid, "functionId", functionIds).collect();
			functions.parallelStream().forEach(func -> func.fill(uid, factory));
		}
	}

	@Override
	public Iterator<Function> iterator() {
		if (functions == null) {
			logger.error("This class has unfilled attribute functions. "
					+ "It looks like it is retrieved from a database. "
					+ "You need to call .retrieveFunctions(ObjectFactory factory) " + "before accessing functions.");
			return null;
		}
		return functions.iterator();
	}

	public transient Object tempObject;

	public BinaryMultiParts converToMultiPart() {
		return new BinaryMultiParts(Arrays.asList(this), 1);
	}
	
	@Override
	protected Binary clone() throws CloneNotSupportedException {
		return (Binary) super.clone();
	}

}
