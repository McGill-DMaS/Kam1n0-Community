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
package ca.mcgill.sis.dmas.kam1n0.symbolic;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;

public abstract class SamplingBox {

	public abstract long sample();

	public static SamplingBox newBoxRandom() {
		return new RandomSequence(-1000l, 1000l);
	}

	public static SamplingBox newBoxManual(long... vals) {
		return new ManualSequnce(vals);
	}

	public List<Long> samples(int size) {
		ArrayList<Long> vals = new ArrayList<>(size);
		IntStream.range(0, size).forEach(ind -> vals.add(sample()));
		return vals;
	}

	public static class RandomSequence extends SamplingBox {

		private long max;
		private long min;

		public RandomSequence(long min, long max) {
			this.max = max;
			this.min = min;
		}

		@Override
		public long sample() {
			return ThreadLocalRandom.current().nextLong(min, max);
		}
	}

	public static class ManualSequnce extends SamplingBox {

		private long[] vals;
		private int index = 0;

		public ManualSequnce(long... vals) {
			this.vals = vals;
		}

		@Override
		public long sample() {
			long val = vals[index];
			index++;
			if (index > vals.length - 1)
				index = vals.length - 1;
			return val;
		}
	}

}
