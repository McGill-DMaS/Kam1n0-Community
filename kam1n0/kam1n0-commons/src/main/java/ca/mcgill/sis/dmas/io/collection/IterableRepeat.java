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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IterableRepeat<T> implements Iterable<T> {

	private static Logger logger = LoggerFactory
			.getLogger(IterableRepeat.class);
	private int repeat = 1;

	Iterable<T> ite;

	public IterableRepeat(Iterable<T> ite_, int repeatingTimes) {
		ite = ite_;
		if (repeatingTimes > 1)
			repeat = repeatingTimes;
	}

	@Override
	public Iterator<T> iterator() {
		return new RepeatIterator();
	}

	public class RepeatIterator implements Iterator<T> {

		private Iterator<T> linesIterator = null;
		private int currentRound = 1;

		public RepeatIterator() {
			if (ite != null)
				linesIterator = ite.iterator();
		}

		@Override
		public boolean hasNext() {
			if (linesIterator == null)
				return false;
			boolean hasNEXT = linesIterator.hasNext();
			if (hasNEXT)
				return true;
			else if (currentRound < repeat) {
				currentRound++;
				linesIterator = ite.iterator();
				if (linesIterator == null) {
					logger.error("Failed to repeat iterator");
					return false;
				}
				hasNEXT = linesIterator.hasNext();
				if (hasNEXT)
					return true;
				else {
					logger.error("Failed to repeat iterator");
					return false;
				}
			} else {
				return false;
			}
		}

		@Override
		public T next() {
			return linesIterator.next();
		}

		@Override
		public void remove() {
			logger.error("Unable to remove element. This is an immutable iterator.");
		}
		
	}
	
	

	public static void main(String [] args){
		List<Integer> list = Arrays.asList(1,2,3,4,5,6,7,8,9,0);
		int numIteration = 1;
		int numOfThread = 2;

		final IterableRepeat<Integer> repeatedIterable = new IterableRepeat<>(
				list, numIteration);

		final ArrayList<Iterable<Integer>> iterables = DmasCollectionOperations
				.split(repeatedIterable, numOfThread);
		
		long tsize = 0;
		for (Iterable<Integer> iterable : iterables) {
			long size = DmasCollectionOperations.count(iterable);
			tsize += size;
			logger.info("iterable size: {}", size);
			logger.info(iterable.toString());
		}
		logger.info("Total size: {}/{}/{}", tsize,
				DmasCollectionOperations.count(repeatedIterable),
				DmasCollectionOperations.count(list)  * numIteration);
	}
}
