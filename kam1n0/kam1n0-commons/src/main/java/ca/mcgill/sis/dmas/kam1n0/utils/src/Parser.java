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

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;

public abstract class Parser {

	private static Logger logger = LoggerFactory.getLogger(Parser.class);

	public void retrieveFullContent(Collection<SrcFunction> srcFuncs, String originalSrcPath, String newSrcPath,
			boolean removeNotFoundFunction) {

		String[] possiblePath = originalSrcPath.split(";");
		Stream<SrcFunction> stream = srcFuncs.stream().peek(func -> {
			for (String ppath : possiblePath)
				func.fileName = func.fileName.replace(ppath, newSrcPath);
		});
		if (removeNotFoundFunction)
			stream = stream.filter(func -> SrcFunctionUtils.fetchContent(func));
		else
			stream = stream.peek(func -> SrcFunctionUtils.fetchContent(func));
		stream = stream.filter(func -> func.content.size() > 0);
		logger.info("Retrieve content for {} src functios.", stream.count());
	}

	public SrcInfo parseSrcFunctionAndLinkeToAssemblyFunction(String sourceCodeDir, String newSourceCodeDir,
			EntryPair<BinarySurrogate, File> binaryFileAndItsCorrespondingAsmFile) {
		return this.parseSrcFunctionAndLinkeToAssemblyFunction(sourceCodeDir, newSourceCodeDir,
				Arrays.asList(binaryFileAndItsCorrespondingAsmFile));
	}

	public abstract SrcInfo parseSrcFunctionAndLinkeToAssemblyFunction(String sourceCodeDir, String newSourceCodeDir,
			List<EntryPair<BinarySurrogate, File>> binaryFileAndItsCorrespondingAsmFile);

	public static enum ParserType {
		injection, pdb, objdump, unstripped
	}

	public abstract String getFileExtension();

	public static Parser getParser(ParserType type) {
		switch (type) {
		case injection:
			return CPPSrcParser.getDefaultImplementation();
		case pdb:
			return new PDBParser();
		case objdump:
			return new ObjDumpParser();
		case unstripped:
			return new UnstrippedParser();
		default:
			return new ObjDumpParser();
		}
	}
}
