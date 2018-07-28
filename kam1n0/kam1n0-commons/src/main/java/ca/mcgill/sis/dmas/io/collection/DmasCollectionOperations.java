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
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;

public class DmasCollectionOperations {

	public static List<String> combinationDuplicated(Set<String> candiates, int size) {
		return combinationDuplicated(candiates, new ArrayList<>(candiates), size - 1);
	}

	private static List<String> combinationDuplicated(Set<String> candiates, List<String> state, int size) {
		if (size == 0) {
			return state;
		} else {
			state = state.stream().flatMap(str -> candiates.stream().map(cand -> {
				return str + "," + cand;
			}).collect(Collectors.toList()).stream()).collect(Collectors.toList());
			return combinationDuplicated(candiates, state, size - 1);
		}

	}

	public static <T> List<List<T>> combination(Collection<T> valus, int size) {
		ArrayList<T> candidates = new ArrayList<>(valus);
		if (size >= candidates.size())
			return Arrays.asList(candidates);
		List<List<T>> result = new ArrayList<>();
		if (size < 1)
			return result;
		candidates.stream().map(cand -> new ArrayList<>(Arrays.asList(cand))).forEach(result::add);
		for (int i = 1; i < size; ++i) {
			List<List<T>> n_result = new ArrayList<>();
			for (List<T> res : result) {
				int j = 0;
				while (candidates.get(j) != res.get(res.size() - 1))
					++j;
				for (j = j + 1; j < candidates.size(); ++j) {
					List<T> newl = new ArrayList<>(res);
					newl.add(candidates.get(j));
					n_result.add(newl);
				}
			}
			result = n_result;
		}
		return result;
	}

	public static <T> Set<T> depulicatedInterset(List<Set<T>> sets) {

		if (sets.size() < 1)
			return null;
		if (sets.size() == 1)
			return sets.get(0);
		Set<T> result = new HashSet<>();

		for (T value : sets.get(0)) {
			boolean add = true;
			for (int i = 1; i < sets.size(); ++i) {
				if (!sets.get(i).contains(value)) {
					add = false;
					break;
				}
			}
			if (add)
				result.add(value);
		}
		return result;
	}

	public static long count(Iterable<?> ite) {
		long res = 0;
		for (@SuppressWarnings("unused")
		Object string : ite) {
			res++;
		}
		return res;
	}

	public static <T> ArrayList<Iterable<T>> split(Iterable<T> iterable, int numberOfSplits) {
		ArrayList<Iterable<T>> result = new ArrayList<Iterable<T>>(numberOfSplits);
		long size = count(iterable);
		int foldSize = (int) (size / numberOfSplits);
		int residue = (int) (size % numberOfSplits);
		if (residue != 0)
			foldSize++;
		for (int i = 0; i < numberOfSplits; i++) {
			int t_start = i * foldSize;

			result.add(Iterables.limit(Iterables.skip(iterable, t_start), foldSize));

			if (residue != 0) {
				residue--;
				if (residue == 0) {
					foldSize--;
				}
			}
		}
		return result;
	}

	public static <T> ArrayList<Iterable<T>> split(Iterable<T> iterable, int numberOfSplits, int numOfRepeat) {
		ArrayList<Iterable<T>> result = new ArrayList<Iterable<T>>(numberOfSplits);
		long size = count(iterable);
		int foldSize = (int) (size / numberOfSplits);
		int residue = (int) (size % numberOfSplits);
		if (residue != 0)
			foldSize++;
		for (int i = 0; i < numberOfSplits; i++) {
			int t_start = i * foldSize;

			Iterable<T> range = Iterables.limit(Iterables.skip(iterable, t_start), foldSize);
			ArrayList<Iterable<T>> ranges = new ArrayList<>();
			for (int j = 0; j < numOfRepeat; j++)
				ranges.add(range);

			result.add(Iterables.concat(ranges));

			if (residue != 0) {
				residue--;
				if (residue == 0) {
					foldSize--;
				}
			}
		}
		return result;
	}

	public static <T> List<List<T>> chopped(List<T> list, final int L) {
		List<List<T>> parts = new ArrayList<List<T>>();
		final int N = list.size();
		for (int i = 0; i < N; i += L) {
			parts.add(new ArrayList<T>(list.subList(i, Math.min(N, i + L))));
		}
		return parts;
	}

	public static void main(String[] args) {
		// List<Integer> list = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);
		// int numIteration = 3;
		// int numOfThread = 3;
		//
		// final ArrayList<Iterable<Integer>> iterables =
		// DmasCollectionOperations.split(list, numOfThread, numIteration);
		//
		// long tsize = 0;
		// for (Iterable<Integer> iterable : iterables) {
		// long size = DmasCollectionOperations.count(iterable);
		// tsize += size;
		// logger.info("iterable size: {}", size);
		// logger.info(iterable.toString());
		// }3
		// logger.info("Total size: {}/{}/{}", tsize,
		// DmasCollectionOperations.count(list) * numIteration);

		combinationDuplicated(Sets.newHashSet("A", "B", "C"), 3).stream().forEach(System.out::println);

		combination(Arrays.asList("A", "B", "C", "D"), 3).stream().forEach(System.out::println);
	}

	public static <A, B, C> Stream<C> zip(Stream<? extends A> a, Stream<? extends B> b,
			BiFunction<? super A, ? super B, ? extends C> zipper) {
		Objects.requireNonNull(zipper);
		@SuppressWarnings("unchecked")
		Spliterator<A> aSpliterator = (Spliterator<A>) Objects.requireNonNull(a).spliterator();
		@SuppressWarnings("unchecked")
		Spliterator<B> bSpliterator = (Spliterator<B>) Objects.requireNonNull(b).spliterator();

		// Zipping looses DISTINCT and SORTED characteristics
		int both = aSpliterator.characteristics() & bSpliterator.characteristics()
				& ~(Spliterator.DISTINCT | Spliterator.SORTED);
		int characteristics = both;

		long zipSize = ((characteristics & Spliterator.SIZED) != 0)
				? Math.min(aSpliterator.getExactSizeIfKnown(), bSpliterator.getExactSizeIfKnown())
				: -1;

		Iterator<A> aIterator = Spliterators.iterator(aSpliterator);
		Iterator<B> bIterator = Spliterators.iterator(bSpliterator);
		Iterator<C> cIterator = new Iterator<C>() {
			@Override
			public boolean hasNext() {
				return aIterator.hasNext() && bIterator.hasNext();
			}

			@Override
			public C next() {
				return zipper.apply(aIterator.next(), bIterator.next());
			}
		};

		Spliterator<C> split = Spliterators.spliterator(cIterator, zipSize, characteristics);
		return (a.isParallel() || b.isParallel()) ? StreamSupport.stream(split, true)
				: StreamSupport.stream(split, false);
	}

	@FunctionalInterface
	public interface TriFunction<A, B, C, D> {

		D apply(A a, B b, C c);

		default <V> TriFunction<A, B, C, V> andThen(Function<? super D, ? extends V> after) {
			Objects.requireNonNull(after);
			return (A a, B b, C c) -> after.apply(apply(a, b, c));
		}
	}

	public static <A, B, C, D> Stream<D> zip(Stream<? extends A> a, Stream<? extends B> b, Stream<? extends C> c,
			TriFunction<? super A, ? super B, ? super C, ? extends D> zipper) {
		Objects.requireNonNull(zipper);
		@SuppressWarnings("unchecked")
		Spliterator<A> aSpliterator = (Spliterator<A>) Objects.requireNonNull(a).spliterator();
		@SuppressWarnings("unchecked")
		Spliterator<B> bSpliterator = (Spliterator<B>) Objects.requireNonNull(b).spliterator();
		@SuppressWarnings("unchecked")
		Spliterator<C> cSpliterator = (Spliterator<C>) Objects.requireNonNull(c).spliterator();

		// Zipping looses DISTINCT and SORTED characteristics
		int both = aSpliterator.characteristics() & bSpliterator.characteristics() & cSpliterator.characteristics()
				& ~(Spliterator.DISTINCT | Spliterator.SORTED);
		int characteristics = both;

		long zipSize = ((characteristics & Spliterator.SIZED) != 0)
				? Arrays.asList(aSpliterator.getExactSizeIfKnown(), bSpliterator.getExactSizeIfKnown(),
						cSpliterator.getExactSizeIfKnown()).stream().mapToLong(val -> val).min().getAsLong()
				: -1;

		Iterator<A> aIterator = Spliterators.iterator(aSpliterator);
		Iterator<B> bIterator = Spliterators.iterator(bSpliterator);
		Iterator<C> cIterator = Spliterators.iterator(cSpliterator);
		Iterator<D> dIterator = new Iterator<D>() {
			@Override
			public boolean hasNext() {
				return aIterator.hasNext() && bIterator.hasNext();
			}

			@Override
			public D next() {
				return zipper.apply(aIterator.next(), bIterator.next(), cIterator.next());
			}
		};

		Spliterator<D> split = Spliterators.spliterator(dIterator, zipSize, characteristics);
		return (a.isParallel() || b.isParallel()) ? StreamSupport.stream(split, true)
				: StreamSupport.stream(split, false);
	}

	@SuppressWarnings("unchecked")
	public static <A> Stream<List<A>> zip(List<? extends Stream<? extends A>> streams) {

		List<Spliterator<A>> spliterators = new ArrayList<>();
		for (Stream<? extends A> stream : streams) {
			spliterators.add((Spliterator<A>) Objects.requireNonNull(stream).spliterator());
		}

		// Zipping looses DISTINCT and SORTED characteristics
		int characteristics = ~(Spliterator.DISTINCT | Spliterator.SORTED);
		for (Spliterator<A> sp : spliterators)
			characteristics &= sp.characteristics();

		long zipSize = ((characteristics & Spliterator.SIZED) != 0)
				? spliterators.stream().mapToLong(val -> val.getExactSizeIfKnown()).min().getAsLong()
				: -1;

		List<Iterator<A>> iterators = new ArrayList<>();
		for (Spliterator<A> sp : spliterators)
			iterators.add(Spliterators.iterator(sp));
		Iterator<List<A>> dIterator = new Iterator<List<A>>() {
			@Override
			public boolean hasNext() {
				return iterators.stream().mapToInt(it -> it.hasNext() ? 1 : 0).sum() == iterators.size();
			}

			@Override
			public List<A> next() {
				return iterators.stream().map(it -> it.next()).collect(Collectors.toList());
			}
		};

		Spliterator<List<A>> split = Spliterators.spliterator(dIterator, zipSize, characteristics);
		boolean parallel = streams.stream().mapToInt(st -> st.isParallel() ? 1 : 0).sum() > 0;
		return parallel ? StreamSupport.stream(split, true) : StreamSupport.stream(split, false);
	}

}
