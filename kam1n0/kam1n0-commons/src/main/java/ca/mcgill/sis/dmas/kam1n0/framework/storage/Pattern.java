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


public class Pattern implements Serializable {

    private static final long serialVersionUID = 8233161495074226150L;
    @KeyedSecondary
    public String patternID;

    @AsString
    public Set<String> clusterList;

    @AsString
    public Map<String, Map<String,Integer>> clscall;

    @AsString
    public String className;


    @AsString
    public String patternName;

    public void addCluster(String clusterName)
    {
        this.clusterList.add(clusterName);
    }


    public Pattern(String patternID, String className, Map<String, Map<String,Integer>> clscall) {
        this.patternID = patternID;
        this.patternName = patternID;
        this.className = className;
        this.clusterList = new HashSet<String>();
        this.clscall = clscall;
    }

    public Pattern() {
        this.patternID = "";
        this.patternName = "";
        this.className = "";
        this.clusterList = new HashSet<String>();
        this.clscall = new HashMap<String, Map<String,Integer>>();
    }
}
