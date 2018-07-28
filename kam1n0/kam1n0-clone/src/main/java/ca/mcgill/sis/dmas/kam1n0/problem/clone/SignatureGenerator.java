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
package ca.mcgill.sis.dmas.kam1n0.problem.clone;

import java.util.ArrayList;

import com.google.common.base.Joiner;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public abstract class SignatureGenerator {
	
	public abstract ArrayList<String> generateSignatureList(Function func);

	public String generateSignature(Function func) {
		StringBuilder sBuilder = new StringBuilder();
		for (String sig : generateSignatureList(func)) {
			sBuilder.append(sig).append(StringResources.STR_TOKENBREAK);
		}
		return sBuilder.toString();
	}

	public String generateSignatureForQuery(Function func) {

		String query = Joiner.on(" OR ").join(generateSignatureList(func));
		if (query.trim().endsWith("OR"))
			query = query.substring(0, query.lastIndexOf("OR"));
		return query;
	}

	public abstract String params();

}
