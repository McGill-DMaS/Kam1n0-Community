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
package ca.mcgill.sis.dmas.kam1n0.utils.hash.vechash;

import java.util.List;

import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class PStableHash extends HashSchema{

	private static final long serialVersionUID = 266418086960523435L;

	public PStableHash(List<String> features, int numberOfHashes) {
		super(numberOfHashes);
		// TODO Auto-generated constructor stub
	}

	@Override
	public String getParams() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] hash(double[] vector) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public double distApprox(byte[] v1, byte[] v2, int length) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public double distReal(double[] v1, double[] v2) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte[] hash(double[] vector, int numberOfBits) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] hash(SparseVector vec, int numberOfBits) {
		// TODO Auto-generated method stub
		return null;
	}

	
	@Override
	public double distReal(SparseVector v1, SparseVector v2) {
		// TODO Auto-generated method stub
		return 0;
	}

	
}
