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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.features;

import java.util.Arrays;
import java.util.HashSet;

public class FreqFeatures {

	public static Features getFeatureFreqByString(String... strs) {
		return new FeatureFreqByString(new HashSet<>(Arrays.asList(strs)));
	}

	public static Features getFeatureMemFreq() {
		return new FeatureMneFreq();
	}

	public static Features getFeatureMemGramFreq(int n) {
		return new FeatureMneGramFreq(n);
	}

	public static Features getFeatureMemOprFreq() {
		return new FeatureMneOprFreq();
	}

	public static Features getFeatureOprFreq() {
		return new FeatureOprFreq();
	}
	
	public static Features getFeatureMemPermFreq(int n){
		return new FeatureMnePermFreq(n);
	}

}
