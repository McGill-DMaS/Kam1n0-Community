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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;


public class Cluster implements Serializable {

	private static final long serialVersionUID = -107741584954373015L;
	@KeyedSecondary
	public String clusterName;
	

	@AsString
	public Set<Long> functionIDList;

	@AsString
	public String className;

	@AsString
	public String patternID;

	@AsString
	public Set<Long> binaryIDList;
	

	@AsString
    public Map<String, Double> classDist;
	
	
	public void addFunction(long funcID)
	{
		this.functionIDList.add(funcID);
	}
	
	public void addBinary(long binID)
	{
		this.binaryIDList.add(binID);
	}
	
	public Cluster(String clusterName, String className) {
		this.clusterName = clusterName;
		this.className = className;
		this.functionIDList = new HashSet<Long>();
		this.binaryIDList = new HashSet<Long>();
		this.classDist = new HashMap<String, Double>();
	}

	public Cluster() {
		this.clusterName = "";
		this.className = "";
		this.patternID = "";
		this.functionIDList = new HashSet<Long>();
		this.binaryIDList = new HashSet<Long>();
		this.classDist = new HashMap<String, Double>();
	}
}
