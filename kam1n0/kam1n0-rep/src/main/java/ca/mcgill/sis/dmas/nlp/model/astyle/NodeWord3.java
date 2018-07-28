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


import java.io.Serializable;
import java.util.Random;

import ca.mcgill.sis.dmas.env.StringResources;

public class NodeWord3 implements Serializable {

	private static final long serialVersionUID = 1982433642098461988L;

	public String token = null;
	public double[] neuIn = null;
	public double[] neuOut1 = null;
	public double[] neuOut2 = null;
	public boolean fixed = false;

	public long freq = 0;
	public double samProb = 1.0;

	public NodeWord3(String token, long freq) {
		this.token = token;
		this.freq = freq;
	}

	public void init(int dim, RandL rl) {
		this.initInLayer(dim, rl);
		this.initOutLayer(dim);
	}

	public void initOutLayer(int dim) {
		this.neuOut1 = new double[dim];
		for (int j = 0; j < dim; ++j)
			neuOut1[j] = 0;
		this.neuOut2 = new double[dim];
		for (int j = 0; j < dim; ++j)
			neuOut2[j] = 0;
	}

	public void initInLayer(int dim, RandL rl) {
		this.neuIn = new double[dim];
		for (int i = 0; i < dim; ++i)
			neuIn[i] = (rl.nextF() - 0.5) / dim;
	}

	@Override
	public String toString() {
		return token;
	}
}
