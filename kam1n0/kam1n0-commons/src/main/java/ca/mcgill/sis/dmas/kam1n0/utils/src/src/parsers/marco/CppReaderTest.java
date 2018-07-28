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
package ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map.Entry;

import javax.annotation.Nonnull;


import com.google.common.base.Charsets;

import ca.mcgill.sis.dmas.io.Lines;

public class CppReaderTest {
	
	
	public static void main(String [] args) throws Exception{
		testCppReader("F:\\reclone v2 macro\\SQLite -v\\SQLite 3080600 -Od\\sqlite3.c");
		
	}
	
	
	public static String testCppReader(String in, Feature... f)
			throws Exception {
		System.out.println("Testing " + in);
		FileReader r = new FileReader(in);
		CppReader p = new CppReader(r);
		p.getPreprocessor()
				.setSystemIncludePath(
						Arrays.asList(new String[] {
								}));
		p.getPreprocessor().addFeatures(f);
		BufferedReader b = new BufferedReader(p);

		StringBuilder out = new StringBuilder();
		String line;
		while ((line = b.readLine()) != null) {
			out.append(line).append("\n");
		}
		b.close();

		for (Entry<String, Macro> macro : p.getPreprocessor().macros.entrySet()) {
			System.out.println(macro.toString());
		}

		return out.toString();
	}
	
	public void testCppReader() throws Exception {
		testCppReader("#include <test0.h>\n", Feature.LINEMARKERS);
	}

	public void testVarargs() throws Exception {
		// The newlines are irrelevant, We want exactly one "foo"
		testCppReader("#include <varargs.c>\n");
	}

	public void testPragmaOnce() throws Exception {
		// The newlines are irrelevant, We want exactly one "foo"
		String out = testCppReader("#include <once.c>\n", Feature.PRAGMA_ONCE);
		System.out.println("foo".equals(out.trim()));
		// assertEquals("foo", out.trim());
	}

	public void testPragmaOnceWithMarkers() throws Exception {
		// The newlines are irrelevant, We want exactly one "foo"
		testCppReader("#include <once.c>\n", Feature.PRAGMA_ONCE,
				Feature.LINEMARKERS);
	}

}
