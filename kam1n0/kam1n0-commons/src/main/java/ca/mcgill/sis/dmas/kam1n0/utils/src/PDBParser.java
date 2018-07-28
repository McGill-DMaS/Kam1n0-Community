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
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;

public class PDBParser extends Parser {

	private static Logger logger = LoggerFactory.getLogger(PDBParser.class);

	public static long BASE_ADDRESS = 0;

	private String excPath;

	public PDBParser() {
		this.excPath = System.getProperty("kam1n0.parser.pdb.dia2dump", System.getProperty("user.dir") + "/dia2dump.exe");
	}

	@Override
	public SrcInfo parseSrcFunctionAndLinkeToAssemblyFunction(String sourceCodeDir, String newSrcPath,
			List<EntryPair<BinarySurrogate, File>> binaryFileAndItsCorrespondingAsmFile) {

		LinkInfo info = new LinkInfo();
		HashMap<Long, SrcFunction> srcFunctions = new HashMap<>();

		binaryFileAndItsCorrespondingAsmFile.forEach(ent -> {
			String pdbFile = ent.value.getAbsolutePath() + getFileExtension();
			BinarySurrogate binary = ent.key;
			File tmpFile = DmasApplication.createTmpFile(StringResources.randomString(10));
			try {
				String[] arg = new String[] { excPath, "-l", DmasApplication.applyDataContext(pdbFile) };
				ProcessBuilder pb = new ProcessBuilder(arg);
				pb.redirectOutput(tmpFile);
				Process p = pb.start();
				p.waitFor();
			} catch (Exception e) {
				logger.error("Failed to parse the pdb file.", e);
				return;
			}

			Lines lines;
			try {
				lines = Lines.fromFile(tmpFile.getAbsolutePath());
			} catch (Exception e) {
				logger.error("Failed to load the pdb file.", e);
				return;
			}
			HashMap<Long, SrcFunction> srcFunctionOffsetMap = new HashMap<>();
			HashMap<Long, SrcFunction> srcFuncDeduplicateMap = new HashMap<>();
			SrcFunction currentFunction = null;
			Long currentSEA = null;

			for (String line : lines) {
				if (line.startsWith("** ")) {
					if (currentFunction != null && currentSEA != null) {
						if (!currentFunction.fileName.endsWith(".asm")) {
							currentFunction.createID();
							if (srcFuncDeduplicateMap.containsKey(currentFunction.id))
								currentFunction = srcFuncDeduplicateMap.get(currentFunction.id);
							else
								srcFuncDeduplicateMap.put(currentFunction.id, currentFunction);

							srcFunctionOffsetMap.put(currentSEA, currentFunction);
						}
					}
					currentFunction = new SrcFunction();
					currentFunction.functionName = line.replaceAll("\\*\\* ", "")
							.replaceAll(StringResources.STR_LINEBREAK, "");
					currentFunction.binaryName = binary.name;
				}
				String[] parts = line.split("\t");
				if (parts.length == 3) {
					// the starting line:
					currentFunction.fileName = parts[2]
							.substring(0, parts[2].lastIndexOf('(') == -1 ? 0 : parts[2].lastIndexOf('(')).trim();
					String[] subParts = parts[1].split(" ");
					currentFunction.s_index = Integer.parseInt(subParts[1]);
					currentSEA = Long.parseLong(subParts[3].split("]")[0].replace("[", ""), 16);
				}
				if (parts.length >= 2) {
					String[] subParts = parts[1].split(" ");
					currentFunction.e_index = Integer.parseInt(subParts[1]);
				}
			}

			final Counter counter = new Counter();
			binary.functions.forEach(asmF -> {
				SrcFunction srcFunction = srcFunctionOffsetMap.get(asmF.sea - BASE_ADDRESS);
				if (srcFunction != null) {
					counter.inc();
					srcFunction.asmFuncID = asmF.id;
					asmF.srcid = srcFunction.id;
					asmF.srcName = srcFunction.functionName;
				}
			});

			info.linked += counter.getVal();
			info.totalAsm += ent.key.functions.size();
			info.totalSrc += srcFunctionOffsetMap.values().size();

			srcFuncDeduplicateMap.values().forEach(func -> srcFunctions.put(func.id, func));

		});

		logger.info("Linked {} functions; total {} srcFunctions; total {} asmFunctions", info.linked, info.totalSrc,
				info.totalAsm);

		logger.info("Retrieving source function content...");
		retrieveFullContent(srcFunctions.values(), sourceCodeDir, newSrcPath, false);

		SrcInfo srcInfo = new SrcInfo();
		srcInfo.srcFuncs = srcFunctions.values();
		srcInfo.linkInfo = info;

		return srcInfo;
	}

	public static void main(String[] args) throws Exception {

		// Environment.init();
		// DmasApplication.contextualize(
		// "E:\\kam1no\\kam1n0-debugSymbol\\zlib-1.2.8\\contrib\\vstudio\\vc11\\x86\\ZlibDllRelease\\");
		// PDBParser parser = new
		// PDBParser("C:\\Users\\Administrator\\git\\Kam1n0\\DIA2Dump\\Debug\\Dia2Dump.exe");
		// DisassemblyFactoryIDA ida = new DisassemblyFactoryIDA("C:\\Program Files
		// (x86)\\IDA 6.7\\");
		// SrcInfo meta = parser.parseSrcFunctionMetaInformation("zlibwapi.pdb",
		// ida.load(DmasApplication.applyDataContext("zlibwapi.dll"),
		// "zlibwapi.dll"));
		// parser.retrieveFullContent(meta, "", "", true);
	}

	@Override
	public String getFileExtension() {
		return ".pdb";
	}

}
