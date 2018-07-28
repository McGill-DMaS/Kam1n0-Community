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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.Lists;

public class Ranker<T> implements Iterable<HeapEntry<T>> {

	public static <E> Ranker<E> countStat(List<E> vals) {
		HashMap<E, Integer> counter = new HashMap<>();
		vals.stream().forEach(cnt -> counter.compute(cnt, (k, v) -> v == null ? 1 : (v + 1)));
		Ranker<E> hp = new Ranker<>();
		counter.forEach((k, v) -> hp.push(v, k));
		return hp;
	}

	public TreeSet<HeapEntry<T>> data = new TreeSet<>();

	public Stream<HeapEntry<T>> stream() {
		return data.stream();
	}

	public HashSet<T> getKeys() {
		return data.stream().map(ent -> ent.value).collect(Collectors.toCollection(HashSet::new));
	}

	public List<HeapEntry<T>> getTopK(int topK) {
		if (topK == 0)
			return new ArrayList<>();
		ArrayList<HeapEntry<T>> ls = this.sortedListEnries(false);
		int end = Math.min(topK, ls.size());
		for (; end < ls.size(); ++end) {
			HeapEntry<T> ent1 = ls.get(end);
			HeapEntry<T> ent2 = ls.get(end - 1);
			if (ent1.score == ent2.score)
				continue;
			else
				break;
		}
		return ls.subList(0, end);

	}

	public int Capacity = Integer.MAX_VALUE;

	public Ranker() {

	}

	public NavigableSet<HeapEntry<T>> subSet(double start, double end) {
		return data.subSet(new HeapEntry<T>(null, start), true, new HeapEntry<T>(null, end), true);
	}

	public Ranker(int capacity) {
		if (capacity < 0)
			Capacity = Integer.MAX_VALUE;
		else
			Capacity = capacity;
	}

	public void clear() {
		data.clear();
	}

	public HeapEntry<T> peekFirst() {
		HeapEntry<T> firstEntry = data.first();
		return firstEntry;
	}

	public HeapEntry<T> peekLast() {
		HeapEntry<T> lastEntry = data.last();
		return lastEntry;
	}

	public HeapEntry<T> pollFirst() {
		HeapEntry<T> firstEntry = data.pollFirst();
		return firstEntry;
	}

	public HeapEntry<T> pollLast() {
		HeapEntry<T> lastEntry = data.pollLast();
		return lastEntry;
	}

	public void push(double score, T value) {
		data.add(new HeapEntry<T>(value, score));
		if (data.size() > Capacity)
			data.pollFirst();
	}

	public int size() {
		return data.size();
	}

	@Override
	public Iterator<HeapEntry<T>> iterator() {
		Iterator<HeapEntry<T>> iterator = new HeapIterator<>(data, true);
		return iterator;
	}

	public ArrayList<T> sortedList(boolean ascend) {

		ArrayList<T> list = new ArrayList<T>();

		for (HeapEntry<T> het : this) {
			list.add(het.value);
		}
		if (ascend) {
			list = new ArrayList<>(Lists.reverse(list));
		}
		return list;
	}

	public ArrayList<HeapEntry<T>> sortedListEnries(boolean ascend) {

		ArrayList<HeapEntry<T>> list = new ArrayList<HeapEntry<T>>();

		for (HeapEntry<T> het : this) {
			list.add(het);
		}
		if (ascend) {
			list = new ArrayList<>(Lists.reverse(list));
		}
		return list;
	}

}
