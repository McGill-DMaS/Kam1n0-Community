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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import ca.mcgill.sis.dmas.env.StringResources;

public class Sentence implements Iterable<String> {

	public String[] tokens;

	public Sentence(List<String> tkns) {
		this.tokens = tkns.toArray(new String[tkns.size()]);
	}

	public Sentence() {
	}

	public String toString() {
		return StringResources.JOINER_TOKEN.join(tokens);
	}

	@Override
	public Iterator<String> iterator() {
		return Arrays.asList(tokens).iterator();
	}

}
