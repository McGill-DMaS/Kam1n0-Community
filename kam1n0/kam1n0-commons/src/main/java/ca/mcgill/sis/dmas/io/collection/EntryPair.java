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

import java.io.Serializable;
import java.util.Iterator;

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.io.Lines;

public class EntryPair<K, V> implements Serializable {
	private static final long serialVersionUID = 925019845208526943L;
	public K key;
	public V value;

	public EntryPair(K key, V value) {
		this.key = key;
		this.value = value;
	}

	public EntryPair() {

	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17, 31).append(key).append(value)
				.toHashCode();
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof EntryPair))
			return false;
		if (obj == this)
			return true;
		EntryPair<K, V> pair = (EntryPair<K, V>) obj;
		return pair.key.equals(this.key) && pair.value.equals(this.value);
	}

	public static PairIterator getIterator(Lines lines) {
		return new PairIterator(lines);
	}

	private static Logger logger = LoggerFactory.getLogger(EntryPair.class);

	private static class PairIterator implements
			Iterator<EntryPair<String, String>> {

		Iterator<String> ite;

		public PairIterator(Lines lines) {
			ite = lines.iterator();
		}

		@Override
		public boolean hasNext() {
			return ite.hasNext();
		}

		@Override
		public EntryPair<String, String> next() {
			String line = ite.next();
			String[] splits = line.split(",");
			EntryPair<String, String> entry = new EntryPair<String, String>();
			if (splits.length < 2) {
				logger.error("Mal-formated string for triplet, should be seperated by ','.");
			} else {
				entry.key = splits[0].trim();
				entry.value = splits[1].trim();
			}
			return entry;
		}

		@Override
		public void remove() {
			logger.error("Unsupported operation: delete/remove");
		}

	}

	@Override
	public String toString() {
		return key + ":" + value;
	}

	public static void main(String[] args) {
		EntryPair<Long, Long> p1 = new EntryPair<Long, Long>(1l, 1l);
		EntryPair<Long, Long> p2 = new EntryPair<Long, Long>(1l, 1l);
		EntryPair<Long, Long> p3 = new EntryPair<Long, Long>(40l, 456345l);

		logger.info("{}", p1.hashCode());
		logger.info("{}", p2.hashCode());
		logger.info("{}", p3.hashCode());
	}
}
