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
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IterableBatch<T> implements Iterable<ArrayList<T>> {

	private static Logger logger = LoggerFactory.getLogger(IterableBatch.class);
	private int groupSize = 500;
	private int repeat = 1;
	private Consumer<Integer>[] repeatHook = null;

	Iterable<T> ite;

	public IterableBatch(Iterable<T> ite_, int groupSize_) {
		ite = ite_;
		groupSize = groupSize_;
		repeat = 1;
	}

	public IterableBatch(Iterable<T> ite_, int groupSize_, int repeatingTimes,
			@SuppressWarnings("unchecked") Consumer<Integer>... repeatHook) {
		ite = ite_;
		groupSize = groupSize_;
		if (repeatingTimes > 1)
			repeat = repeatingTimes;
		this.repeatHook = repeatHook;
	}

	@Override
	public Iterator<ArrayList<T>> iterator() {
		return new BatchIterator();
	}

	public class BatchIterator implements Iterator<ArrayList<T>> {

		private Iterator<T> linesIterator = null;
		private int currentRound = 1;

		public BatchIterator() {
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
				if (repeatHook != null && repeatHook.length > 0)
					Arrays.stream(repeatHook).filter(h -> h != null).forEach(h -> h.accept(currentRound));
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
					// logger.error("Failed to repeat iterator");
					return false;
				}
			} else {
				if (repeatHook != null && repeatHook.length > 0)
					Arrays.stream(repeatHook).filter(h -> h != null).forEach(h -> h.accept(currentRound));
				return false;
			}
		}

		@Override
		public ArrayList<T> next() {
			ArrayList<T> sentences = new ArrayList<>();
			do {
				T line = linesIterator.next();
				sentences.add(line);
			} while (linesIterator.hasNext() && sentences.size() < groupSize);
			return sentences;
		}

		@Override
		public void remove() {
			logger.error("Unable to remove element. This is an immutable iterator.");
		}

	}

	// public static void main(String[] args) throws Exception {
	// DmasApplication.contextualize("D:\\dataset\\CIKM\\");
	//
	// // test sentences
	// Sentences sentences = CIKM2014QueryDataset.testingData("test.text");
	// System.out.println(DmasCollectionOperations.count(sentences));
	//
	// // test batch mode
	// IterableBatch<Sentence> ib = new IterableBatch<>(sentences, 500);
	// int count = 0;
	// for (ArrayList<Sentence> arrayList : ib) {
	// count += arrayList.size();
	// }
	// System.out.println(count);
	//
	// // test iterative batch mode
	// ib = new IterableBatch<>(sentences, 123, 1);
	// count = 0;
	// for (ArrayList<Sentence> arrayList : ib) {
	// count += arrayList.size();
	// }
	// System.out.println(count);
	//
	// // test thread safe mode
	// final IteratorSafeGen<Sentence> safeSentences = new IteratorSafeGen<>(
	// ib);
	//
	// int numThreads = 5;
	// Pool pool = new Pool(numThreads);
	// final long[] counters = new long[5];
	// Arrays.fill(counters, 0);
	//
	// for (int i = 0; i < 5; i++) {
	//
	// final int index = i;
	// pool.submit(new Task() {
	// @Override
	// public void run() throws Exception {
	// counters[index] = DmasCollectionOperations
	// .count(safeSentences.subIterable());
	// }
	// });
	// }
	//
	// pool.waiteForCompletion();
	//
	// long sum = 0;
	// for (int i = 0; i < counters.length; ++i) {
	// sum += counters[i];
	// }
	// System.out.println(sum);
	//
	// }
}
