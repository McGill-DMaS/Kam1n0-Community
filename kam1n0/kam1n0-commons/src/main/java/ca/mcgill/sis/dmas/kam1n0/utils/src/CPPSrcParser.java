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

import gnu.trove.set.hash.TLongHashSet;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.utils.src.parsers.CppSrcParserImp;
import ca.mcgill.sis.dmas.kam1n0.utils.src.parsers.SrcLinkerByInjection;

public abstract class CPPSrcParser extends Parser {

	public static CPPSrcParser getDefaultImplementation() {
		return new CppSrcParserImp();
	}

	protected static Logger logger = LoggerFactory.getLogger(CPPSrcParser.class);

	public abstract ArrayList<SrcFunction> find(String binaryAbsolutPath, File file, List<String> headers)
			throws Exception;

	public abstract String declareVaraible(String variableName, String value);

	public abstract Pattern getDeclarationPattern();

	public abstract String[] getValidFileExtensions();

	public List<String> includes = new ArrayList<>();

	public ListMultimap<File, SrcFunction> findAll(String dir, boolean deduplicateFunctions) {
		dir = DmasApplication.applyDataContext(dir);
		ListMultimap<File, SrcFunction> functions = ArrayListMultimap.create();
		TLongHashSet functionIDS = new TLongHashSet();
		final File dirf = new File(dir);
		Path directory = Paths.get(dirf.getAbsolutePath());
		List<String> extensions = Arrays.asList(this.getValidFileExtensions());
		try {
			Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {

					File srcFile = file.toFile();

					String fname = srcFile.getName();

					// validation: (valid file or not)
					int extIndex = fname.lastIndexOf('.');
					if (extIndex < 0)
						extIndex = 0;
					if (!extensions.contains(fname.substring(extIndex, fname.length())))
						return FileVisitResult.CONTINUE;

					File lfile = file.toFile();
					ArrayList<SrcFunction> functionsInFile;
					try {
						ArrayList<String> includedPaths = new ArrayList<>();
						// add binary dir
						includedPaths.add(dirf.getAbsolutePath());
						// add current dir
						includedPaths.add(lfile.getParentFile().getAbsolutePath());
						// add system library dirs
						includedPaths.addAll(includes);
						functionsInFile = find(dirf.getAbsolutePath(), lfile,
								// belows are included libraries
								includedPaths);
					} catch (Exception e) {
						logger.error("Failed to extract functions from file: " + lfile.getAbsolutePath(), e);
						return FileVisitResult.CONTINUE;
					}
					for (SrcFunction function : functionsInFile) {
						if (deduplicateFunctions && !functionIDS.contains(function.id)) {
							functions.put(lfile, function);
						}
					}
					return FileVisitResult.CONTINUE;
				}
			});
		} catch (IOException e) {
			logger.error("Failed to extract functions from dir : " + dir, e);
		}
		return functions;
	}

	public SrcInfo parseSrcFunctionAndLinkeToAssemblyFunction(String sourceCodeDir, String newSrcDir,
			List<EntryPair<BinarySurrogate, File>> binaryFileAndItsCorrespondingAsmFile) {
		List<SrcFunction> srcFuncs = new ArrayList<>(findAll(sourceCodeDir, true).values());
		retrieveFullContent(srcFuncs, sourceCodeDir, newSrcDir, true);
		List<FunctionSurrogate> asmFuncs = binaryFileAndItsCorrespondingAsmFile.stream()
				.flatMap(ent -> ent.key.functions.stream()).collect(Collectors.toList());
		SrcLinkerByInjection.linkToAssemblySurrogateConsiderInlines(srcFuncs, asmFuncs);
		LinkInfo info = new LinkInfo();
		info.totalAsm = asmFuncs.size();
		info.totalSrc = srcFuncs.size();
		info.linked = (int) srcFuncs.stream().filter(func -> func.asmFuncID != -1).count();
		SrcInfo srcInfo = new SrcInfo();
		srcInfo.linkInfo = info;
		srcInfo.srcFuncs = srcFuncs;
		return srcInfo;
	}

	public static enum SrcParserType {
		CPP, JAVA, PYTHON, AUTOMATIC
	}

	public static CPPSrcParser getParser(SrcParserType type) {
		switch (type) {
		case CPP:
			return new CppSrcParserImp();
		default:
			throw new UnsupportedOperationException();
		}
	}

	public abstract String replaceDelcaration(String string, String newDeclaration);

}
