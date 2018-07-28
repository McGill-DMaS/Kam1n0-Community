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
package ca.mcgill.sis.dmas.kam1n0.utils.src.parsers;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.eclipse.cdt.core.dom.ast.IASTNode;
import org.eclipse.cdt.core.dom.ast.IASTTranslationUnit;
import org.eclipse.cdt.core.dom.ast.gnu.cpp.GPPLanguage;
import org.eclipse.cdt.core.parser.DefaultLogService;
import org.eclipse.cdt.core.parser.FileContent;
import org.eclipse.cdt.core.parser.IParserLogService;
import org.eclipse.cdt.core.parser.IScannerInfo;
import org.eclipse.cdt.core.parser.IncludeFileContentProvider;
import org.eclipse.cdt.core.parser.ScannerInfo;
import org.eclipse.cdt.internal.core.dom.parser.cpp.CPPASTFunctionDefinition;

import com.google.common.base.Charsets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;
import ca.mcgill.sis.dmas.kam1n0.utils.src.CPPSrcParser;

public class CppSrcParserImp extends CPPSrcParser {

	/**
	 * Identify function defintion from a cpp/c file
	 * 
	 * @param file
	 * @return list of function: (line_start, line_end)
	 * @throws Exception
	 */
	@Override
	public ArrayList<SrcFunction> find(String binaryAbsolutPath, File file, List<String> headers) throws Exception {

		// extract macros map:
		Map<String, String> definedSymbols = CppMacroExtractor.extractSymbolicMacros(file.getAbsolutePath(), headers);

		FileContent fileContent = FileContent.createForExternalFileLocation(file.getAbsolutePath());

		// Map<String, String> definedSymbols = new HashMap<String, String>();
		String[] includePaths = headers.toArray(new String[headers.size()]);// new
																			// String[0];
		IScannerInfo info = new ScannerInfo(definedSymbols, includePaths);
		IParserLogService log = new DefaultLogService();

		IncludeFileContentProvider emptyIncludes = IncludeFileContentProvider.getEmptyFilesProvider();

		int opts = 8;
		IASTTranslationUnit translationUnit = GPPLanguage.getDefault().getASTTranslationUnit(fileContent, info,
				emptyIncludes, null, opts, log);
		// get includes:
		// IASTPreprocessorIncludeStatement[] includes = translationUnit
		// .getIncludeDirectives();
		// for (IASTPreprocessorIncludeStatement include : includes) {
		// System.out.println("include - " + include.getName());
		// }

		ArrayList<SrcFunction> functions = new ArrayList<SrcFunction>();
		lookup(functions, translationUnit, Lines.readAllAsArray(file.getAbsolutePath(), Charsets.UTF_8, false),
				binaryAbsolutPath, file.getAbsolutePath().replace(binaryAbsolutPath, ""));

		return functions;
	}

	private static void lookup(ArrayList<SrcFunction> functions, IASTNode current, ArrayList<String> cachedFile,
			String binaryName, String fileName) {
		IASTNode[] children = current.getChildren();

		if (current instanceof CPPASTFunctionDefinition) {
			String fname = ((CPPASTFunctionDefinition) current).getDeclarator().getName().toString();
			int s_ind = current.getFileLocation().getStartingLineNumber();
			int e_ind = current.getFileLocation().getEndingLineNumber();
			s_ind--;
			if (s_ind < 0)
				s_ind = 0;

			SrcFunction function = new SrcFunction();
			function.binaryName = binaryName;
			function.functionName = fname + "-" + s_ind;
			function.fileName = fileName;
			function.content = new ArrayList<>(cachedFile.subList(s_ind, e_ind));
			function.s_index = s_ind;
			function.e_index = e_ind;
			function.createID();
			functions.add(function);
		}

		for (IASTNode iastNode : children) {
			lookup(functions, iastNode, cachedFile, binaryName, fileName);
		}
	}

	private static String[] validExtension = new String[] { ".cpp", ".c", ".h" };

	@Override
	public String[] getValidFileExtensions() {
		return validExtension;
	}

	/**
	 * printf("%d", 0x96a9345c);
	 */
	@Override
	public String declareVaraible(String variableName, String value) {
		return StringResources.JOINER_TOKEN.join("volatile int", variableName, "=", value, ";");
	}

	private static Pattern injectedPatter = Pattern
			.compile("volatile[\\s]+int[\\s]+injectedDmasVar[0-9a-fA-F]{8}[\\s]+=[\\s]+0x[0-9a-fA-F]{8}[\\s]+;");

	@Override
	public Pattern getDeclarationPattern() {
		return injectedPatter;
	}

	public static void main(String[] args) throws Exception {
		// Environment.init();
		// SrcParser parser = new CppParser();
		// ArrayList<SrcFunction> functions = parser
		// .find("test",
		// new File(
		// "F:\\Kam1n0\\Ziplib\\zlib-1.2.8\\contrib\\minizip\\ioapi.c"),
		// Arrays.asList(new String[] {
		//
		//
		// "F:\\Kam1n0\\Ziplib\\zlib-1.2.8\\contrib\\minizip\\" }));
		// logger.info(StringResources.JOINER_LINE.join(functions));

		CPPSrcParser parser = new CppSrcParserImp();

		System.out.println(parser.replaceDelcaration("{ volatile int injectedDmasVare5370f9f = 0xe5370f9f ;",
				parser.declareVaraible("injectedDmasVarc5682f03", "0xc5682f03")));
	}

	@Override
	public String replaceDelcaration(String string, String newDeclaration) {
		return injectedPatter.matcher(string).replaceAll(newDeclaration);
	}

	@Override
	public String getFileExtension() {
		return StringResources.STR_EMPTY;
	}

	// @Override
	// public void setInjectedValue(SrcFunction function) {
	// for (String line : function.content) {
	// Matcher matcher = injectedPatter.matcher(line);
	// if (matcher.find()) {
	// String identifier = matcher.group(1);
	// function.injectedID = identifier;
	// return;
	// }
	// }
	//
	// }

	/**
	 * T E S T.
	 */

	// private static Logger logger = LoggerFactory.getLogger(CppParser.class);
	//
	// public static void main(String[] args) throws Exception {
	// File dirv7 = new File("D:\\dataset\\Some data from MR\\all\\zlib127SRC");
	// File dirv8 = new File("D:\\dataset\\Some data from MR\\all\\zlib128SRC");
	// DmasApplication.contextualize("D:\\dataset\\zlib");
	//
	// File[] v7s = dirv7.listFiles();
	// File[] v8s = dirv8.listFiles();
	//
	// String outDirV7s = DmasApplication.applyDataContext("outDirV7s/");
	// (new File(outDirV7s)).mkdirs();
	// String outDirV8s = DmasApplication.applyDataContext("outDirV8s/");
	// (new File(outDirV8s)).mkdirs();
	// CppParser lookup = new CppParser();
	// for (File file : v7s) {
	// String fname = file.getName();
	// try {
	// HashMap<String, int[]> functions = lookup.find(file);
	// Lines flines = Lines.fromFile(file.getAbsolutePath());
	// for (Entry<String, int[]> index : functions.entrySet()) {
	// Lines function = Lines.selectAsLines(flines,
	// index.getValue()[0], index.getValue()[1]);
	// Lines.flushToFile(function,
	// outDirV7s + fname + "." + index.getKey() + ".cpp");
	// }
	// } catch (Exception e) {
	// logger.error(
	// "Failed to extract functions from :"
	// + file.getAbsolutePath(), e);
	// }
	// }
	//
	// for (File file : v8s) {
	// String fname = file.getName();
	// try {
	// HashMap<String, int[]> functions = lookup.find(file);
	// Lines flines = Lines.fromFile(file.getAbsolutePath());
	// for (Entry<String, int[]> index : functions.entrySet()) {
	// Lines function = Lines.selectAsLines(flines,
	// index.getValue()[0], index.getValue()[1]);
	// Lines.flushToFile(function,
	// outDirV8s + fname + "." + index.getKey() + ".cpp");
	// }
	// } catch (Exception e) {
	// logger.error(
	// "Failed to extract functions from :"
	// + file.getAbsolutePath(), e);
	// }
	// }
	//
	// }

}
