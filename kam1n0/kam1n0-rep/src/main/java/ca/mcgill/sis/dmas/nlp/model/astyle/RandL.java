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
package ca.mcgill.sis.dmas.nlp.model.astyle;


public class RandL {
	public long nextRandom = 1;

	public RandL(long seed) {
		this.nextRandom = seed;
	}

	public long nextR() {
		nextRandom = nextRandom * 25214903917L + 11;
		return nextRandom;
	}

	public int nextResidue(int max) {
		return (int) Long.remainderUnsigned(this.nextR(), max);
	}

	public double nextF() {
		double val = 
				((this.nextR() & 0xFFFF) / 65536d);
		return val;
	}

	public static void main(String[] args) {
		RandL rl = new RandL(0);
		for (int i = 0; i < 1000; ++i) {
			System.out.println(rl.nextF());
		}
	}
}
