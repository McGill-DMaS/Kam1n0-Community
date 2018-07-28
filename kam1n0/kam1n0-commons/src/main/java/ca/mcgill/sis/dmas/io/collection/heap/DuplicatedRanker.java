package ca.mcgill.sis.dmas.io.collection.heap;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Stream;

import com.google.common.collect.TreeMultimap;

public class DuplicatedRanker<T extends Comparable<T>> {

	private TreeMultimap<Double, T> data = TreeMultimap.<Double, T>create((d1, d2) -> Double.compare(d2, d1),
			(v1, v2) -> v1.compareTo(v2));
	private int topk = -1;

	public DuplicatedRanker() {
		this.topk = -1;
	}

	public DuplicatedRanker(int topk) {
		this.topk = topk;
	}

	public void push(Double score, T value) {
		data.put(score, value);
		if (this.topk > 0 && data.keySet().size() > this.topk) {
			data.keySet().pollLast();
		}
	}

	public String toString() {
		return data.toString();
	}

	public Set<Entry<Double, T>> entries() {
		return data.entries();
	}

	public Stream<Entry<Double, T>> stream() {
		return this.entries().stream();
	}

	public Collection<T> values() {
		return data.values();
	}

	public Set<T> valueSet() {
		return new HashSet<>(this.values());
	}

	public static void main(String[] args) {
		DuplicatedRanker<Long> ranker = new DuplicatedRanker<>(3);
		ranker.push(0.99, 1l);
		ranker.push(0.99, 2l);
		ranker.push(0.99, 3l);
		ranker.push(0.99, 4l);
		ranker.push(0.96, 5l);
		ranker.push(0.98, 6l);
		ranker.push(0.97, 7l);
		ranker.push(0.95, 8l);
		ranker.push(0.94, 9l);
		System.out.println(ranker.values());
	}
}
