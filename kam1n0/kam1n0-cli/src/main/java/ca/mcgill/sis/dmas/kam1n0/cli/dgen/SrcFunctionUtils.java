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
package ca.mcgill.sis.dmas.kam1n0.cli.dgen;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;

import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;

public class SrcFunctionUtils {

	private static Logger logger = LoggerFactory.getLogger(SrcFunctionUtils.class);

	public static boolean fetchContent(SrcFunction function) {
		try {

			if (!(new File(function.fileName)).exists()) {
				//logger.warn("{} not found in file system: {}", function.functionName, function.fileName);
				return false;
			}

			ArrayList<String> lines = Lines.readAllAsArray(function.fileName, Charsets.UTF_8, false);
			lines.subList(function.s_index - 1 > 0 ? function.s_index - 1 : 0, function.e_index)
					.forEach(line -> function.content.add(line));
			return true;
		} catch (Exception e) {
			// logger.error("Failed to fetch the function content.", e);
			return false;
		}
	}

	public static void write(Iterable<SrcFunction> srcfunctions, File outputFile) throws Exception {
		JsonFactory jfactory = new JsonFactory();
		JsonGenerator jGenerator = jfactory.createGenerator(outputFile, JsonEncoding.UTF8).setCodec(new ObjectMapper());
		for (SrcFunction srcFunction : srcfunctions) {
			jGenerator.writeObject(srcFunction);
		}
		jGenerator.close();
	}

	public static void writePretty(Iterable<SrcFunction> srcfunctions, File outputFile) throws Exception {
		JsonFactory jfactory = new JsonFactory();
		JsonGenerator jGenerator = jfactory.createGenerator(outputFile, JsonEncoding.UTF8).useDefaultPrettyPrinter()
				.setCodec(new ObjectMapper());
		for (SrcFunction srcFunction : srcfunctions) {
			jGenerator.writeObject(srcFunction);
		}
		jGenerator.close();
	}

	public static SrcFunctions getSrcFunctions(File file) throws Exception {
		return new SrcFunctions(file);
	}

	public static SrcFunctions getSrcFunctionsNotExcept(File file) {
		try {
			return new SrcFunctions(file);
		} catch (Exception e) {
			logger.error("Failed to load src functions.", e);
			return null;
		}
	}

	public static ArrayList<SrcFunction> readAll(File file) throws Exception {
		ArrayList<SrcFunction> list = new ArrayList<>();
		for (SrcFunction srcFunction : getSrcFunctions(file)) {
			list.add(srcFunction);
		}
		return list;
	}

	public static class SrcFunctions implements Iterable<SrcFunction> {

		File file;

		public SrcFunctions(File file) throws Exception {
			this.file = file;
		}

		@Override
		public Iterator<SrcFunction> iterator() {
			try {
				return (new ObjectMapper()).reader(SrcFunction.class).readValues(file);
			} catch (Exception e) {
				logger.error("Failed to load functions from the file:" + file.getAbsolutePath(), e);
			}
			;
			return null;
		}
	}
}
