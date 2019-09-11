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
package ca.mcgill.sis.dmas.kam1n0.commons.defs;

import java.io.Serializable;
import java.util.Set;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.RawOperations;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.RawRegisterList;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class Architecture implements Serializable {

	private static final long serialVersionUID = -8443410803609589918L;

	public static enum ArchitectureType {
		metapc, arm, ppc, mips, tms320c6, mc68, c6502;

		public ArchitectureRepresentation retrieveDefinition() {
			return ArchitectureRepresentation
					.load(KamResourceLoader.loadFile("architectures/" + this.toString() + ".xml"));
		}

		public AsmLineNormalizationResource retrieveNormalizationResource() {
			return AsmLineNormalizationResource.retrieve(this);
		}

		public Set<String> retrieveRawRegisters() {
			return RawRegisterList.get(this);
		}

		public Set<String> retrieveRawOperations() {
			return RawOperations.get(this);
		}
	}

	public static enum InstructionSize {
		b32, b64
	}

	public static enum Endianness {
		be, le
	}

	public ArchitectureType type = ArchitectureType.metapc;
	public InstructionSize size = InstructionSize.b32;
	public Endianness endian = Endianness.be;

	public ArchitectureType getType() {
		return type;
	}

	public void setType(ArchitectureType type) {
		this.type = type;
	}

	public InstructionSize getSize() {
		return size;
	}

	public void setSize(InstructionSize size) {
		this.size = size;
	}

	public Endianness getEndian() {
		return endian;
	}

	public void setEndian(Endianness endian) {
		this.endian = endian;
	}

	@Override
	public String toString() {
		return type.toString() + ":" + size.toString() + ":" + endian;
	}

}
