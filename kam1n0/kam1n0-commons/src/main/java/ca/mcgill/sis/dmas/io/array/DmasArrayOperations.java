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
package ca.mcgill.sis.dmas.io.array;

import gnu.trove.list.array.TIntArrayList;
import gnu.trove.set.hash.TIntHashSet;
import gnu.trove.set.hash.TLongHashSet;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;

public class DmasArrayOperations {

	public static <T> ArrayList<T> deduplicateUnstable(final ArrayList<T> vals) {
		HashSet<T> uvals = new HashSet<>();
		ArrayList<T> rvals = new ArrayList<T>();
		for (T val : vals) {
			if (uvals.add(val)) {
				rvals.add(val);
			}
		}
		return rvals;
	}

	/* This for non primitive types */
	@SuppressWarnings("unchecked")
	public static <T> T[] concatenate(T[]... elements) {
		T[] C = null;
		for (T[] element : elements) {
			if (element == null)
				continue;
			if (C == null)
				C = (T[]) Array.newInstance(element.getClass().getComponentType(), element.length);
			else
				C = resize(C, C.length + element.length);

			System.arraycopy(element, 0, C, C.length - element.length, element.length);
		}

		return C;
	}

	public static int[] concatenate(int[]... elements) {
		int[] C = null;
		for (int[] element : elements) {
			if (element == null)
				continue;
			if (C == null)
				C = new int[element.length];
			else
				C = resize(C, C.length + element.length);

			System.arraycopy(element, 0, C, C.length - element.length, element.length);
		}
		return C;
	}

	public static byte[] concatenate(byte[]... elements) {
		byte[] C = null;
		for (byte[] element : elements) {
			if (element == null)
				continue;
			if (C == null)
				C = new byte[element.length];
			else
				C = resize(C, C.length + element.length);

			System.arraycopy(element, 0, C, C.length - element.length, element.length);
		}
		return C;
	}

	public static byte[] concatenate(byte[] array, byte... values) {
		byte[] C = null;
		if (array == null)
			return C;
		C = array.clone();

		if (values == null)
			return C;

		C = resize(C, C.length + values.length);

		System.arraycopy(values, 0, C, C.length - values.length, values.length);

		return C;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static <T> T resize(T array, int newSize) {
		int oldSize = java.lang.reflect.Array.getLength(array);
		Class elementType = array.getClass().getComponentType();
		Object newArray = java.lang.reflect.Array.newInstance(elementType, newSize);
		int preserveLength = Math.min(oldSize, newSize);
		if (preserveLength > 0)
			System.arraycopy(array, 0, newArray, 0, preserveLength);
		return (T) newArray;
	}

	public static <T> T[] shuffle(T[] array) {
		return shuffle(array, new Random());
	}

	public static <T> T[] shuffle(T[] array, Random rnd) {
		for (int i = array.length; i > 1; i--)
			swap(array, i - 1, rnd.nextInt(i));
		return array;
	}

	public static void swap(int[] array, int x, int y) {
		int tmpIndex = array[x];
		array[x] = array[y];
		array[y] = tmpIndex;
	}

	public static void swap(long[] array, int x, int y) {
		long tmpIndex = array[x];
		array[x] = array[y];
		array[y] = tmpIndex;
	}

	public static void swap(double[] array, int x, int y) {
		double tmpIndex = array[x];
		array[x] = array[y];
		array[y] = tmpIndex;
	}

	public static void swap(boolean[] array, int x, int y) {
		boolean tmpIndex = array[x];
		array[x] = array[y];
		array[y] = tmpIndex;
	}

	public static <T> void swap(T[] array, int x, int y) {
		T tmpIndex = array[x];
		array[x] = array[y];
		array[y] = tmpIndex;
	}

	public static int[] intersection(int[] arr, int[] arr2) {
		TIntArrayList lst = new TIntArrayList();
		int i = 0, j = 0;
		while (i < arr.length && j < arr2.length) {
			if (arr[i] == arr2[j]) {
				if (lst.isEmpty() || lst.get(lst.size() - 1) < arr[i])
					lst.add(arr[i]);
				i++;
				j++;
			} else if (arr[i] > arr2[j]) {
				j++;
			} else {
				i++;
			}
		}

		return lst.toArray();
	}

	public static <T extends Comparable<T>> ArrayList<T> intersection(T[] arr, T[] arr2) {
		ArrayList<T> lst = new ArrayList<T>();
		int i = 0, j = 0;
		while (i < arr.length && j < arr2.length) {
			if (arr[i] == arr2[j]) {
				if (lst.isEmpty() || lst.get(lst.size() - 1).compareTo(arr[i]) < 0)
					lst.add(arr[i]);
				i++;
				j++;
			} else if (arr[i].compareTo(arr2[j]) > 0) {
				j++;
			} else {
				i++;
			}
		}

		return lst;
	}

	public static int[] intersectionUnsorted(int[] arr, int[] arr2) {
		TIntHashSet set = new TIntHashSet();
		TIntHashSet toReturn = new TIntHashSet();
		for (int a : arr) {
			set.add(a);
		}

		for (int a : arr2) {
			if (set.contains(a)) {
				toReturn.add(a);
			}
		}

		return toReturn.toArray();
	}

	public static long[] intersectionUnsorted(long[] arr, long[] arr2) {
		TLongHashSet set = new TLongHashSet();
		TLongHashSet toReturn = new TLongHashSet();
		for (long a : arr) {
			set.add(a);
		}

		for (long a : arr2) {
			if (set.contains(a)) {
				toReturn.add(a);
			}
		}

		return toReturn.toArray();
	}

	public static int[] union(int[] a, int[] b) {
		TIntHashSet set = new TIntHashSet();
		set.addAll(a);
		set.addAll(b);
		return set.toArray();
	}

	public static long[] union(long[] a, long[] b) {
		TLongHashSet set = new TLongHashSet();
		set.addAll(a);
		set.addAll(b);
		return set.toArray();
	}

	public static ArrayList<Long> toNewList(long[] vals) {
		ArrayList<Long> ls = new ArrayList<>(vals.length);
		for (int i = 0; i < vals.length; ++i)
			ls.add(vals[i]);
		return ls;
	}

	public static ArrayList<Integer> toNewList(int[] vals) {
		ArrayList<Integer> ls = new ArrayList<>(vals.length);
		for (int i = 0; i < vals.length; ++i)
			ls.add(vals[i]);
		return ls;
	}

	public static ArrayList<Double> toNewList(double[] vals) {
		ArrayList<Double> ls = new ArrayList<>(vals.length);
		for (int i = 0; i < vals.length; ++i)
			ls.add(vals[i]);
		return ls;
	}

	public static ArrayList<Float> toNewList(float[] vals) {
		ArrayList<Float> ls = new ArrayList<>(vals.length);
		for (int i = 0; i < vals.length; ++i)
			ls.add(vals[i]);
		return ls;
	}

	public static ArrayList<Byte> toNewList(byte[] vals) {
		ArrayList<Byte> ls = new ArrayList<>(vals.length);
		for (int i = 0; i < vals.length; ++i)
			ls.add(vals[i]);
		return ls;
	}

	final protected static char[] encoding = "0123456789ABCDEF".toCharArray();

	public static String toHexs(int[] arr) {
		char[] encodedChars = new char[arr.length * 4 * 2];
		for (int i = 0; i < arr.length; i++) {
			int v = arr[i];
			int idx = i * 4 * 2;
			for (int j = 0; j < 8; j++) {
				encodedChars[idx + j] = encoding[(v >>> ((7 - j) * 4)) & 0x0F];
			}
		}
		return new String(encodedChars);
	}

	public static String toHexs(byte[] arr) {
		char[] encodedChars = new char[arr.length * 2];
		for (int i = 0; i < arr.length; i++) {
			byte v = arr[i];
			int idx = i * 2;
			for (int j = 0; j < 2; j++) {
				encodedChars[idx + j] = encoding[(v >>> ((1 - j) * 4)) & 0x0F];
			}
		}
		return new String(encodedChars);
	}

	public static byte[] toBytes(int[] vals) {
		byte[] bytes = new byte[vals.length * 4];
		for (int ind = 0; ind < vals.length; ++ind) {
			bytes[ind * 4] = (byte) (vals[ind] >> 24);
			bytes[ind * 4 + 1] = (byte) (vals[ind] >> 16);
			bytes[ind * 4 + 2] = (byte) (vals[ind] >> 8);
			bytes[ind * 4 + 3] = (byte) vals[ind];
		}
		return bytes;
	}

	public static boolean allZero(double[] vals) {
		for (double d : vals) {
			if (d != 0)
				return false;
		}
		return true;
	}

}
