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
package ca.mcgill.sis.dmas.kam1n0.vex;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VexCall {
	public int regparms;
	public String name;
	public long address_unsigned;
	public int mcx_mask_usigned;

	public VexCall(@JsonProperty("regparms") int regparms, @JsonProperty("name") String name,
			@JsonProperty("address_unsigned") long address_unsigned,
			@JsonProperty("mcx_mask_usigned") int mcx_mask_usigned) {
		super();
		this.regparms = regparms;
		this.name = name;
		this.address_unsigned = address_unsigned;
		this.mcx_mask_usigned = mcx_mask_usigned;
	}

}
