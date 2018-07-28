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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.DisassemblyFactoryIDA;

public class ObjDumpParser extends Parser {

	private static Logger logger = LoggerFactory.getLogger(ObjDumpParser.class);

	private static Pattern funcStart = Pattern.compile("(?<adr>[0-9a-f]+)\\s\\<(?<fn>[\\S]+)\\>:");

	public ObjDumpParser() {
	}

	boolean debug = false;

	@Override
	public SrcInfo parseSrcFunctionAndLinkeToAssemblyFunction(String sourceCodeDir, String newSrcPath,
			List<EntryPair<BinarySurrogate, File>> binaryFileAndItsCorrespondingAsmFile) {

		LinkInfo info = new LinkInfo();
		HashMap<Long, SrcFunction> srcFunctions = new HashMap<>();

		binaryFileAndItsCorrespondingAsmFile.forEach(ent -> {
			// check whether the corresponding debug symbol exists:
			File symbolFile = new File(ent.value.getAbsolutePath() + this.getFileExtension());

			if (!symbolFile.exists()) {
				logger.error("The corresponding {} file {} for {} does not exist. skipping.", this.getFileExtension(),
						symbolFile.getAbsolutePath(), ent.value.getAbsolutePath());
				return;
			}

			Lines lines;
			try {
				lines = Lines.fromFile(symbolFile.getAbsolutePath());
			} catch (Exception e) {
				logger.error("Failed to load the pdb file.", e);
				return;
			}
			HashMap<Long, SrcFunction> srcFunctionOffsetMap = new HashMap<>();
			SrcFunction currentFunction = null;
			String currentScope = StringResources.STR_EMPTY;
			Long startEA = null;

			for (String line : lines) {
				// if (line.trim().endsWith("():")) {
				Matcher matcher = funcStart.matcher(line.trim());
				if (matcher.find()) {
					if (currentFunction != null && startEA != null) {
						currentFunction.createID();

						// if
						// (srcFuncDeduplicateMap.containsKey(currentFunction.id))
						// currentFunction =
						// srcFuncDeduplicateMap.get(currentFunction.id);
						// else
						// srcFuncDeduplicateMap.put(currentFunction.id,
						// currentFunction);

						// if (SrcFunctionUtils.fetchContent(currentFunction))
						srcFunctionOffsetMap.put(startEA, currentFunction);
						// else if (debug)
						// System.out.println("src not found: " +
						// currentFunction.functionName);

						currentFunction = null;
						startEA = null;
						currentScope = StringResources.STR_EMPTY;
					}

					try {
						startEA = Long.parseLong(matcher.group("adr"), 16);
					} catch (Exception e) {
						logger.error("Failed to parse address from {}", line);
						startEA = null;
					}

					currentFunction = new SrcFunction();
					currentFunction.binaryName = ent.key.name;
					currentFunction.s_index = Integer.MAX_VALUE;
					currentFunction.e_index = Integer.MIN_VALUE;
					currentFunction.fileName = StringResources.STR_EMPTY;
					// currentFunction.functionName = line.replace("():",
					// "").replaceAll("\\*\\* ", "")
					// .replaceAll(StringResources.STR_LINEBREAK, "").trim();
					currentFunction.functionName = matcher.group("fn");
					continue;
				}
				if (currentFunction == null)
					continue;

				if (line.trim().endsWith("():")) {
					currentScope = line.replace("():", "").replaceAll("\\*\\* ", "")
							.replaceAll(StringResources.STR_LINEBREAK, "").trim();
					// if(!currentScope.equals(currentFunction.functionName))
					// logger.info("Inlined calls of {} in {}", currentScope,
					// currentFunction.functionName);
				}

				if (line.startsWith("/") && line.contains(":") && currentScope.equals(currentFunction.functionName)) {
					// currentFunction.fileName = line.replace(srcPathOriginal,
					// srcPathNow);
					String fileName = line.substring(0, line.lastIndexOf(":"));
					currentFunction.fileName = fileName;
					int discriminator = line.lastIndexOf("(");
					if (discriminator == -1)
						discriminator = line.length();
					int addr = -1;
					try {
						addr = Integer.parseInt(line.substring(line.lastIndexOf(":") + 1, discriminator).trim());
					} catch (Exception e) {
						logger.error("mal-formeted line:" + line, e);
						continue;
					}
					if (currentFunction.s_index > addr)
						currentFunction.s_index = addr;
					if (currentFunction.e_index < addr)
						currentFunction.e_index = addr;
				}
				// else if (startEA == null) {
				// try {
				// startEA = Long.parseLong(line.split(":")[0].trim(), 16);
				// } catch (Exception e) {
				// startEA = null;
				// }
				// }
			}

			final Counter counter = new Counter();
			ent.key.functions.forEach(asmF -> {
				SrcFunction srcFunction = srcFunctionOffsetMap.get(asmF.sea);
				if (srcFunction != null) {
					if (debug && !srcFunction.functionName.trim().equalsIgnoreCase(asmF.name.trim()))
						System.out.println(
								"Symobl matches but name not matched: " + srcFunction.functionName + " " + asmF.name);
					counter.inc();
					srcFunction.asmFuncID = asmF.id;
					asmF.srcid = srcFunction.id;
					asmF.srcName = srcFunction.functionName;

				} else if (debug)
					System.out.println(Long.toHexString(asmF.sea) + " " + Long.toHexString(asmF.see) + " " + asmF.name);
			});

			info.linked += counter.getVal();
			info.totalAsm += ent.key.functions.size();
			info.totalSrc += srcFunctionOffsetMap.values().size();

			srcFunctionOffsetMap.values().stream().filter(func -> func.fileName.trim().length() > 0)
					.forEach(func -> srcFunctions.put(func.id, func));

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

		// Environment.init(true);
		// DmasApplication
		// .contextualize("E:\\kam1no\\kam1n0-debugSymbol\\zlib-1.2.8\\contrib\\vstudio\\vc11\\x86\\ZlibDllRelease\\");
		// ObjDumpParser parser = new ObjDumpParser(
		// "C:\\Users\\Administrator\\git\\Kam1n0\\DIA2Dump\\Debug\\Dia2Dump.exe");

		// parser.parse("zlibwapi.pdb", ida.load(
		// DmasApplication.applyDataContext("zlibwapi.dll"),
		// "zlibwapi.dll"));

		Environment.init();
		DisassemblyFactory ida = DisassemblyFactoryIDA.getDefaultDisassemblyFactory();
		ObjDumpParser parser = new ObjDumpParser();
		String file = "C:\\Users\\lynn\\Desktop\\test-arm\\sqlite\\sqlite-amalgamation-3100200\\a.out";
		SrcInfo info = parser.parseSrcFunctionAndLinkeToAssemblyFunction("", "",
				new EntryPair<>(ida.load(file), new File(file)));

		parser.retrieveFullContent(info.srcFuncs, "/home/steven/arm/sqlite/sqlite-amalgamation-3100200",
				"C:\\Users\\lynn\\Desktop\\test-arm\\sqlite\\sqlite-amalgamation-3100200\\", true);
	}

	@Override
	public String getFileExtension() {
		return ".txt";
	}

}
