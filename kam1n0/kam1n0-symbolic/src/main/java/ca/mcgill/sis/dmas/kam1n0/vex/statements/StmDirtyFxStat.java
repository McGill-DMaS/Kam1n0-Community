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
package ca.mcgill.sis.dmas.kam1n0.vex.statements;

import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.StmDirtyEffect;

public class StmDirtyFxStat {
	public StmDirtyEffect fx;
	public int offset_unsigned;
	public int size_unsigned;
	public int nReapts_unsigned;
	public int repeat_len_unsigned;

	public StmDirtyFxStat(@JsonProperty("fx") StmDirtyEffect fx, @JsonProperty("offset_unsigned") int offset_unsigned,
			@JsonProperty("size_unsigned") int size_unsigned, @JsonProperty("nReapts_unsigned") int nReapts_unsigned,
			@JsonProperty("repeat_len_unsigned") int repeat_len_unsigned) {
		super();
		this.fx = fx;
		this.offset_unsigned = offset_unsigned;
		this.size_unsigned = size_unsigned;
		this.nReapts_unsigned = nReapts_unsigned;
		this.repeat_len_unsigned = repeat_len_unsigned;
	}
}
