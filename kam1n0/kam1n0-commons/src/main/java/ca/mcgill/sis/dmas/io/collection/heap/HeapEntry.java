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
package ca.mcgill.sis.dmas.io.collection.heap;

public class HeapEntry<K> implements Comparable<HeapEntry<K>> {
	public K value;
	public double score;

	public HeapEntry(K value, double score) {
		this.value = value;
		this.score = score;
	}

	@Override
	public int compareTo(HeapEntry<K> o) {
		if (this.score > o.score) {
			return 1;
		} else {
			return -1;
		}
	}
	
	public String toString(){
		return Double.toString(score) + " " + value.toString();
	}

}