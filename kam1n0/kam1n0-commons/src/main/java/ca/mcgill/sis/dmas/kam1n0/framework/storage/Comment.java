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
package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import java.io.Serializable;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;

public class Comment implements Serializable {

	public static enum CommentType {
		user, regular, repeatable, anterior, posterior
	}

	private static final long serialVersionUID = 1L;

	@ObjectFactoryMultiTenancy.KeyedSecondary(index = 0)
	public long functionId;

	@ObjectFactoryMultiTenancy.KeyedSecondary(index = 1)
	public String functionOffset;

	@ObjectFactoryMultiTenancy.KeyedSecondary(index = 2)
	public String userName = StringResources.STR_EMPTY;

	@ObjectFactoryMultiTenancy.KeyedSecondary(index = 3)
	public long date;

	public String comment = StringResources.STR_EMPTY;

	@AsString
	public CommentType type = CommentType.regular;

	public Comment() {
	}

	public Comment(long fid, String comment, CommentType type, long date, String userName, String offset) {
		this.functionId = fid;
		this.comment = comment;
		this.type = type;
		this.date = date;
		this.userName = userName;
		this.functionOffset = offset;
	}

}


