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
package ca.mcgill.sis.dmas.kam1n0.utils.src;

import java.util.List;

public class LinkInfo {
	public int linked;
	public int totalAsm;
	public int totalSrc;

	public double getLinkedRatio() {
		return linked * 1.0 / totalSrc;
	}

	public double getExternalRatio() {
		return linked * 1.0 / totalAsm;
	}

	public LinkInfo add(LinkInfo other) {
		this.linked += other.linked;
		this.totalAsm += other.totalAsm;
		this.totalSrc += other.totalSrc;
		return this;
	}

	public static LinkInfo merge(List<LinkInfo> infos) {
		LinkInfo info = new LinkInfo();
		for (LinkInfo lInfo : infos) {
			info.add(lInfo);
		}
		return info;
	}

	@Override
	public String toString() {
		return "Linked " + linked + " functions; total " + totalSrc + " srcFunctions; total " + totalAsm
				+ " asmFunctions";
	}
}