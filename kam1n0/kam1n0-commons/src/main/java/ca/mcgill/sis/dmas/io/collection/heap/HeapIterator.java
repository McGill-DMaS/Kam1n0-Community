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

import java.util.Iterator;
import java.util.TreeSet;

public class HeapIterator<T> implements Iterator<HeapEntry<T>> {

	public HeapIterator(TreeSet<HeapEntry<T>> data, boolean decend) {
		if (data == null)
			ite = null;
		else{
			if(decend)
				ite = data.descendingIterator();
			else {
				ite = data.iterator();
			}
		}
	}

	Iterator<HeapEntry<T>> ite;

	@Override
	public boolean hasNext() {
		if (ite != null)
			return ite.hasNext();
		else {
			return false;
		}
	}

	@Override
	public HeapEntry<T> next() {
		if (ite != null)
			return ite.next();
		else {
			return null;
		}
	}

	@Override
	public void remove() {
		ite.remove();
	}

}