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
package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.DisassemblyFactoryIDA;

/**
 * does not need to be a thread safe implementation
 * 
 * @author steven
 *
 */
public abstract class DisassemblyFactory {

	public int batchSize = 10000;
	public boolean rebaseToZero = false;
	public boolean cleanStack = false;

	public BinarySurrogate load(String filePath) throws Exception {
		return this.load(filePath, filePath);
	}

	public BinarySurrogate load(String filePath, boolean rebaseToZero) throws Exception {
		return this.load(filePath, filePath, rebaseToZero);
	}

	public BinarySurrogate load(String filePath, String newName) throws Exception {
		return this.loadAsMultiPart(filePath, newName, batchSize, rebaseToZero, cleanStack).merge();
	}

	public BinarySurrogate load(String filePath, String newName, boolean rebaseToZero) throws Exception {
		return this.loadAsMultiPart(filePath, newName, batchSize, rebaseToZero, cleanStack).merge();
	}

	public abstract BinarySurrogateMultipart loadAsMultiPart(String binaryFilePath, String newNameForBinary,
			int batchSize, boolean rebaseToZero, boolean cleanStack) throws Exception;

	public BinarySurrogateMultipart loadAsMultiPart(String binaryFilePath, String newNameForBinary) throws Exception {
		return this.loadAsMultiPart(binaryFilePath, newNameForBinary, batchSize, rebaseToZero, cleanStack);
	}

	public BinarySurrogateMultipart loadAsMultiPart(String binaryFilePath) throws Exception {
		return this.loadAsMultiPart(binaryFilePath, binaryFilePath, batchSize, rebaseToZero, cleanStack);
	}

	public abstract void init();

	public abstract void close();

	private static Logger logger = LoggerFactory.getLogger(DisassemblyFactory.class);

	public static DisassemblyFactory getDefaultDisassemblyFactory() {
		DisassemblyFactoryIDA factory = new DisassemblyFactoryIDA(
				);
		factory.init();
		return factory;
	}

	public static HashMap<File, BinarySurrogate> diassemble(List<File> buidDirs, final Pattern... filePatterns) {
		DisassemblyFactory disassemblyFactory = getDefaultDisassemblyFactory();
		HashMap<File, BinarySurrogate> asmFiles = new HashMap<>();
		ArrayList<FunctionSurrogate> asmFunctions = new ArrayList<>();
		for (File buildDir : buidDirs) {
			try {
				ArrayList<File> binaries = DmasFileOperations.select(buildDir.getAbsolutePath(), filePatterns);
				logger.info("Detected {} binary files for {}.", binaries.size(), buildDir.getAbsolutePath());
				for (File binary : binaries) {
					logger.info("Disassembling {}", binary.getName());
					try {
						BinarySurrogate binarySurrogate = disassemblyFactory.load(binary.getAbsolutePath());
						asmFunctions.addAll(binarySurrogate.functions);
						asmFiles.put(binary, binarySurrogate);
					} catch (Exception e) {
						logger.error("Failed to disasemble the given binary file " + binary.getAbsolutePath(), e);
					}
				}
			} catch (Exception e) {
				logger.error("Failed to search through directory " + buildDir.getAbsolutePath(), e);
			}
		}
		return asmFiles;
	}

	public static BinarySurrogate disassembleSingle(File file) {
		return disassembleSingle(file, getDefaultDisassemblyFactory());
	}

	public static BinarySurrogate disassembleSingle(File file, DisassemblyFactory factory) {
		try {
			return factory.load(file.getAbsolutePath(), file.getName());
		} catch (Exception e) {
			logger.error("Failed to disassembly " + file, e);
			return null;
		}
	}

}
