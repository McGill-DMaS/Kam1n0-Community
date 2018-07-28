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
package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

import java.io.Serializable;

public class NormalizationSetting implements Serializable {

	private static final long serialVersionUID = -5035994985963353659L;

	public static NormalizationSetting New() {
		return new NormalizationSetting();
	}

	/**
	 * Register normalization level
	 */
	public static enum NormalizationLevel {
		NORM_NONE, // no normalization
		NORM_ROOT, // normlize all registers to REG;
					// all memory variables to MEM;
		NORM_TYPE, // normalize registers to their corresponding types
					// all memory variables to MEM
		NORM_LENGTH, // normalize general registers according to their
						// corresponding bit length
						// normalize memory variables according to their
						// corresponding bit length
		NORM_TYPE_LENGTH; //

		public static String[] names() {
			NormalizationLevel[] states = NormalizationLevel.values();
			String[] names = new String[states.length];
			for (int i = 0; i < states.length; i++) {
				names[i] = states[i].name();
			}
			return names;
		}

	}

	public NormalizationLevel normalizationLevel = NormalizationLevel.NORM_TYPE;

	public boolean normalizeConstant = true;
	public boolean normalizeOperation = true;

	public NormalizationLevel getNormalizationLevel() {
		return normalizationLevel;
	}

	public void setNormalizationLevel(NormalizationLevel normalizationLevel) {
		this.normalizationLevel = normalizationLevel;
	}

	public boolean getNormalizeConstant() {
		return normalizeConstant;
	}

	public void setNormalizeConstant(boolean normalizeConstant) {
		this.normalizeConstant = normalizeConstant;
	}

	public boolean getNormalizeOperation() {
		return normalizeOperation;
	}

	public void setNormalizeOperation(boolean normalizeOperation) {
		this.normalizeOperation = normalizeOperation;
	}

}
