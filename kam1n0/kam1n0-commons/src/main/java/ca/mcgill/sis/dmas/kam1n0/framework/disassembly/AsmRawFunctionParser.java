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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;

public class AsmRawFunctionParser implements RawFunctionParser {

	public static Pattern blockMarker = Pattern.compile("^([a-zA-Z0-9_]+)[\\s]*:");
	private AsmLineNormalizationResource res;

	public AsmRawFunctionParser(AsmLineNormalizationResource res) {
		this.res = res;
	}

	/***
	 * Simple construction (control flow graph)
	 * 
	 * @param lines
	 * @return
	 * @throws Exception
	 */
	public Binary fromPlainText(List<String> lines, String functionName, String binaryName,
			Map<String, String[]> otherParams) throws Exception {

		// used to find the first line of assembly code:
		int startingIndex = 0;
		Iterator<String> ite = lines.iterator();
		while (ite.hasNext()) {
			String currentLine = ite.next().replaceAll("\\s", " ").trim();
			String mm = currentLine.split(" ")[0].toUpperCase();
			if (res.operationMap.containsKey(mm) || res.operationJmps.contains(mm))
				break;
			String marker = parseBlockMarkerFromPlanText(currentLine);
			if (marker != StringResources.STR_EMPTY)
				break;
			startingIndex++;
		}
		if (startingIndex >= lines.size() - 1)
			throw new Exception("Can not locate the first valid line of asm code. ");

		FunctionSurrogate functionInputSurrogate = new FunctionSurrogate();
		functionInputSurrogate.sea = startingIndex;
		functionInputSurrogate.see = lines.size() - 1; // inclusive

		ArrayList<BlockSurrogate> blocks = new ArrayList<>();

		HashMap<String, Long> blockMap = new HashMap<>();

		// stateful values:
		ArrayList<List<String>> builder = new ArrayList<>();
		int seaAddress = startingIndex;
		String currentMarker = StringResources.STR_EMPTY;
		long blockIndex = 0;

		for (int index = startingIndex; index < lines.size(); ++index) {
			String currentLine = lines.get(index).replaceAll("\\s", " ").trim();
			if (currentLine.startsWith(";"))
				continue;
			if (currentLine.startsWith("align"))
				continue;
			if (currentLine.endsWith("endp"))
				continue;

			String[] parts = res.extractParts(currentLine);
			// System.out.println(currentLine + " " + Arrays.toString(parts));

			String marker = parseBlockMarkerFromPlanText(currentLine);
			String[] callee = parseJumpFromAsm(parts);

			// check the starting condition of a block:
			if (marker != StringResources.STR_EMPTY || callee[0] != StringResources.STR_EMPTY) {

				// if this block has code, added to the map
				if (builder.size() != 0// asmBuilder.length() != 0
						|| callee[0] != StringResources.STR_EMPTY) {

					// adding the block sequencially.
					BlockSurrogate currentBlock = new BlockSurrogate();
					blocks.add(currentBlock);

					// add to the map if this block has a marker:
					if (currentMarker != StringResources.STR_EMPTY)
						blockMap.put(currentMarker.toUpperCase(), blockIndex);

					if (callee[0] != StringResources.STR_EMPTY) {
						// a jmp is part of this block
						// but a 'main:' marker belongs to the next block
						ArrayList<String> ls = new ArrayList<>();
						builder.add(ls);
						ls.add(String.format("0x%04X", index & 0xFFFFF));
						ls.addAll(Arrays.asList(parts));
						// asmBuilder.append(
						// + " "
						// + currentLine).append(
						// StringResources.STR_LINEBREAK);
					}

					currentBlock.src = builder;
					currentBlock.id = blockIndex;
					currentBlock.sea = seaAddress;
					currentBlock.eea = index - 1; // inclusive
					if (!marker.trim().equals(StringResources.STR_EMPTY))
						currentBlock.name = marker;
					else
						currentBlock.name = "No_caller_" + Integer.toHexString(seaAddress).toUpperCase();
				}

				// start a new block:
				builder = new ArrayList<>();

				// a 'main:' marker will belong to the new block
				if (marker != StringResources.STR_EMPTY) {
					// check if the rest part exists after the block marker:
					String theRestPart = blockMarker.matcher(currentLine).replaceAll("").trim();
					if (theRestPart.length() > 0 && !theRestPart.startsWith(";")) {
						String[] resparts = res.extractParts(currentLine);
						// asmBuilder.append(theRestPart).append(
						// StringResources.STR_LINEBREAK);
						ArrayList<String> ls = new ArrayList<>();
						builder.add(ls);
						ls.addAll(Arrays.asList(resparts));
					}

				}

				seaAddress = index;
				currentMarker = marker;
				blockIndex++;
			} else {
				// if it does not satisfy the block starting conditions:
				if (currentLine.length() != 0) {
					ArrayList<String> ls = new ArrayList<>();
					builder.add(ls);
					ls.add(String.format("0x%04X", index & 0xFFFFF));
					ls.addAll(Arrays.asList(parts));
				}
			}
		}
		// last block:
		if (/* currentMarker != StringResources.STR_EMPTY && */builder.size() != 0) {
			// adding the block sequencially.
			BlockSurrogate currentBlock = new BlockSurrogate();
			blocks.add(currentBlock);
			// add to the map if this block has a marker:
			if (currentMarker != StringResources.STR_EMPTY)
				blockMap.put(currentMarker.toUpperCase(), blockIndex);

			currentBlock.src = builder;
			currentBlock.id = blockIndex;
			currentBlock.sea = seaAddress;
			currentBlock.eea = lines.size() - 1; // inclusive
			currentBlock.name = currentMarker;
		}

		// creating call graph:
		for (int i = 0; i < blocks.size(); ++i) {
			BlockSurrogate blockInputSurrogate = blocks.get(i);
			boolean endingBlock = false;
			boolean unconditionalJum = false;
			for (List<String> asmLine : blockInputSurrogate) {
				if (asmLine != null && asmLine.size() > 2) {
					if (!res.operationJmps.contains(asmLine.get(1)))
						continue;
					if (asmLine.get(1).equalsIgnoreCase("JMP"))
						unconditionalJum = true;
					if (asmLine.size() > 2) {
						String[] opnd = AsmLineNormalizer.asmLineTokenizerBySpace.split(asmLine.get(2));
						String jmpAddr = StringResources.STR_EMPTY;
						int ind = 0;
						do {
							jmpAddr = opnd[ind];
							ind++;
						} while (res.jmpKeywords.contains(jmpAddr.toUpperCase()) && ind < opnd.length);
						if (jmpAddr == StringResources.STR_EMPTY)
							continue;

						Long id = blockMap.get(jmpAddr.trim().toUpperCase());
						if (id != null)
							blockInputSurrogate.call.add(id);
					}
				}

				if (isEndingBlock(asmLine)) {
					endingBlock = true;
				}
			}
			// the next block will be executed sequentially.
			// only if this block does not include a return operation.
			if (i != blocks.size() - 1 && !endingBlock && !unconditionalJum) {
				blockInputSurrogate.call.add(blocks.get(i + 1).id);
			}
		}

		functionInputSurrogate.blocks = blocks;
		functionInputSurrogate.name = functionName;
		functionInputSurrogate.id = functionInputSurrogate.sea;

		BinarySurrogate binarySurrogate = new BinarySurrogate();
		binarySurrogate.functions.add(functionInputSurrogate);
		binarySurrogate.name = binaryName;
		binarySurrogate.hash = binaryName.hashCode();
		binarySurrogate.processRawBinarySurrogate();

		return binarySurrogate.toBinary();

	}

	public String parseBlockMarkerFromPlanText(String asmLine) {
		Matcher matcher = blockMarker.matcher(asmLine);
		if (!matcher.find() || matcher.groupCount() < 1)
			return StringResources.STR_EMPTY;
		else
			return matcher.group(1);
	}

	public String[] parseJumpFromAsm(String[] asmLine) {
		String[] jmpCommand = new String[] { StringResources.STR_EMPTY, StringResources.STR_EMPTY };
		if (asmLine == null)
			return jmpCommand;
		List<String> tokens = Arrays.asList(asmLine);
		if (tokens.size() < 2)
			return jmpCommand;
		String jmp = tokens.get(0).toUpperCase();
		if (!res.operationJmps.contains(jmp))
			return jmpCommand;
		jmpCommand[0] = jmp;
		for (int i = 1; i < tokens.size(); ++i) {
			String ctoken = tokens.get(i).toUpperCase();
			if (ctoken.startsWith(";"))
				return null;
			if (res.jmpKeywords.contains(ctoken))
				continue;
			if (ctoken.endsWith(";"))
				ctoken = ctoken.substring(0, ctoken.length() - 1);
			jmpCommand[1] = ctoken.toUpperCase();
			return jmpCommand;
		}
		return null;

	}

	// index + retn
	// e.g. retn 0CH
	public boolean isEndingBlock(List<String> tokens) {
		if (tokens.size() < 2)
			return false;
		if (tokens.get(1).equalsIgnoreCase("ret") || tokens.get(1).equalsIgnoreCase("retn"))
			return true;
		return false;
	}

	public static void main(String[] args) throws Exception {
		// ArrayList<String> asm = Lines.readAllAsArray("exampleAsmFunction.txt",
		// Charsets.UTF_8, false);
		//
		// BinarySurrogate binary = fromPlainText(asm, "test", "test");
		//
		// System.out.println((new
		// ObjectMapper()).writerWithDefaultPrettyPrinter().writeValueAsString(binary));

	}
}
