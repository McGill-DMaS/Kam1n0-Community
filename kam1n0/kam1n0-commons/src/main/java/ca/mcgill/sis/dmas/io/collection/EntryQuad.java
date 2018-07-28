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
package ca.mcgill.sis.dmas.io.collection;

import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.io.Lines;

public class EntryQuad<T> {
	public T value0;
	public T value1;
	public T value2;
	public T value3;
	
	public EntryQuad(T v0, T v1, T v2, T v3){
		value0 = v0;
		value1 = v1;
		value2 = v2;
		value3 = v3;
	}
	
	public EntryQuad(){
		
	}
	
	public static QuadIterator getIterator(Lines lines){
		return new QuadIterator(lines);
	}
	
	private static Logger logger = LoggerFactory.getLogger(EntryQuad.class);

	private static class QuadIterator implements Iterator<EntryQuad<String>> {

		Iterator<String> ite;
		
		public QuadIterator(Lines lines) {
			ite = lines.iterator();
		}

		@Override
		public boolean hasNext() {
			return ite.hasNext();
		}

		@Override
		public EntryQuad<String> next() {
			String line = ite.next();
			String [] splits = line.split(",");
			EntryQuad<String> entry = new EntryQuad<String>();
			if(splits.length != 4){
				logger.error("Mal-formated string for triplet, should be seperated by ','.");
			}else {
				entry.value0 = splits[0].trim();
				entry.value1 = splits[1].trim();
				entry.value2 = splits[2].trim();
				entry.value3 = splits[3].trim();
			}
			return entry;
		}

		@Override
		public void remove() {
			logger.error("Unsupported operation: delete/remove");
		}

	}
}
