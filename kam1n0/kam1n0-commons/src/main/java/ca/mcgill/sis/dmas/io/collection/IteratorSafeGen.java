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
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IteratorSafeGen<T> {

	private static Logger logger = LoggerFactory.getLogger(IteratorSafeGen.class);

	private final Iterator<ArrayList<T>> l_itrator;

	public IteratorSafeGen(IterableBatch<T> itr) {
		this.l_itrator = itr.iterator();
	}

	@SafeVarargs
	public IteratorSafeGen(Iterable<T> itr, int batch_size, int iteration, Consumer<Integer>... repeatHook) {
		this.l_itrator = (new IterableBatch<T>(itr, batch_size, iteration, repeatHook)).iterator();
	}

	@SuppressWarnings("unchecked")
	public IteratorSafeGen(Iterable<T> itr) {
		this.l_itrator = (new IterableBatch<T>(itr, 100, 1)).iterator();
	}

	public SafeIterable subIterable() {
		return new SafeIterable();
	}

	public class SafeIterable implements Iterable<T> {

		@Override
		public Iterator<T> iterator() {
			return new SafeIterator();
		}

		public class SafeIterator implements Iterator<T> {

			ArrayList<T> cache = new ArrayList<>();
			int ind = 0;

			@Override
			public boolean hasNext() {
				if (cache == null || cache.size() == 0 || ind >= cache.size()) {
					synchronized (l_itrator) {
						if (l_itrator.hasNext()) {
							cache = l_itrator.next();
							ind = 0;
							if (cache == null || cache.size() == 0)
								return false;
							else {
								return true;
							}
						} else {
							return false;
						}
					}
				} else if (ind < cache.size() && ind >= 0) {
					return true;
				} else {
					return false;
				}
			}

			T line = null;

			@Override
			public T next() {
				line = cache.get(ind);
				ind++;
				return line;
			}

			@Override
			public void remove() {
				logger.error("unsupport action: remove");
			}

		}

	}

	public static void main(String[] args) {
		List<Integer> ls = IntStream.range(0, 1000000).mapToObj(ind -> new Integer(ind)).collect(Collectors.toList());
		IteratorSafeGen<Integer> gen = new IteratorSafeGen<>(ls, 100, 3);
		new Pool(5).start(ind -> {
			Counter counter = Counter.zero();
			gen.subIterable().forEach(val -> counter.inc());
			System.out.println(counter.getVal());
		}).waiteForCompletion();
	}

}
