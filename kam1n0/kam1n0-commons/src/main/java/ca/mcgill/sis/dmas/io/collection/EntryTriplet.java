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

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;

public class EntryTriplet<T, K, D> {
	public T value0;
	public K value1;
	public D value2;

	public EntryTriplet(T v0, K v1, D v2) {
		value0 = v0;
		value1 = v1;
		value2 = v2;
	}

	public EntryTriplet() {

	}

	@Override
	public String toString() {
		return StringResources.JOINER_TOKEN_CSV.join(value0, value1, value2);
	}

	public static TripletIterator getIterator(Lines lines) {
		return new TripletIterator(lines);
	}

	private static Logger logger = LoggerFactory.getLogger(EntryTriplet.class);

	private static class TripletIterator implements
			Iterator<EntryTriplet<String, String, String>> {

		Iterator<String> ite;

		public TripletIterator(Lines lines) {
			ite = lines.iterator();
		}

		@Override
		public boolean hasNext() {
			return ite.hasNext();
		}

		@Override
		public EntryTriplet<String, String, String> next() {
			String line = ite.next();
			String[] splits = line.split(",");
			EntryTriplet<String, String, String> entry = new EntryTriplet<>();
			if (splits.length != 3) {
				logger.error("Mal-formated string for triplet, should be seperated by ','.");
			} else {
				entry.value0 = splits[0].trim();
				entry.value1 = splits[1].trim();
				entry.value2 = splits[2].trim();
			}
			return entry;
		}

		@Override
		public void remove() {
			logger.error("Unsupported operation: delete/remove");
		}

	}
}
