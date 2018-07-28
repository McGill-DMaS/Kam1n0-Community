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
package ca.mcgill.sis.dmas.kam1n0.app.clone.adata;

import java.io.Serializable;
import java.util.ArrayList;

import org.codehaus.jackson.annotate.JsonIgnore;

import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;

public class FunctionCloneDetectionResultForWeb implements Serializable {

	@JsonIgnore
	private static final long serialVersionUID = 4298161337172134038L;

	public FunctionDataUnit function;

	public ArrayList<FunctionCloneEntryForWeb> clones = new ArrayList<>();

	public ArrayList<Integer> maximunSplit = new ArrayList<>();

	public int subGraphMinSize;

}
