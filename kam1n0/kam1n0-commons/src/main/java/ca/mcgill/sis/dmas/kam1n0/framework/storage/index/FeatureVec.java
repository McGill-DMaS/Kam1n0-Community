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
package ca.mcgill.sis.dmas.kam1n0.framework.storage.index;

import java.io.Serializable;

public class FeatureVec implements Serializable{
	
	private static final long serialVersionUID = -2685510852986430618L;
	public long key = -1;
	public double [] vector;
	
	public FeatureVec(long key, double [] vector){
		this.key = key;
		this.vector = vector;
	}
	
	public long getKey() {
		return key;
	}
	public void setKey(long key) {
		this.key = key;
	}
	public double[] getVector() {
		return vector;
	}
	public void setVector(double[] vector) {
		this.vector = vector;
	}
	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	

}
