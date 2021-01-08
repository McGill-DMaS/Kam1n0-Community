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

import gnu.trove.map.hash.TLongLongHashMap;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.io.collection.heap.Ranker;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Comment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BinarySurrogate implements Iterable<FunctionSurrogate> {

	private static Logger logger = LoggerFactory.getLogger(BinarySurrogate.class);

	public String fileNameFromName() {
		return (new File(name)).getName();
	}

	// name of the binary
	public String name;
	public String md5 = StringResources.STR_EMPTY;
	public long hash;
	public ArrayList<FunctionSurrogate> functions = new ArrayList<FunctionSurrogate>();

	// architecture info
	public Architecture architecture = new Architecture();

	private static ObjectMapper mapper = new ObjectMapper();

	@Override
	public int hashCode() {
		return Long.hashCode(hash);
	}

	@JsonIgnore
	@Override
	public Iterator<FunctionSurrogate> iterator() {
		return functions.iterator();
	}

	public Binary toBinary() {
		Binary obinary = new Binary();
		obinary.binaryId = this.hash;
		obinary.binaryName = this.name;
		obinary.functionIds = new HashSet<>();
		obinary.architecture = this.architecture;
		obinary.functions = new ArrayList<>();
		this.functions.stream().peek(func -> obinary.functions.add(toFunction(func))) //
				.map(func -> func.id) //
				.forEach(obinary.functionIds::add);
		obinary.numFunctions = obinary.functions.size();
		return obinary;
	}

	public Binary toBinaryWithFilters(Predicate<? super FunctionSurrogate> predicate) {
		Binary obinary = new Binary();
		obinary.binaryId = this.hash;
		obinary.binaryName = this.name;
		obinary.functionIds = new HashSet<>();
		obinary.architecture = this.architecture;
		obinary.functions = new ArrayList<>();
		this.functions.stream()
				//
				.filter(predicate).peek(func -> obinary.functions.add(toFunction(func))) //
				.map(func -> func.id) //
				.forEach(obinary.functionIds::add);
		obinary.numFunctions = obinary.functions.size();
		return obinary;
	}

	public Function toFunction(FunctionSurrogate func) {
		Function ofunc = new Function();
		ofunc.binaryId = this.hash;
		ofunc.binaryName = this.name;
		ofunc.blockIds = new HashSet<>();
		ofunc.callingFunctionIds = func.call;
		ofunc.ccalls = func.api;
		ofunc.functionId = func.id;
		ofunc.functionName = func.name;
		ofunc.startingAddress = func.sea;
		ofunc.srcId = func.srcid;
		ofunc.srcName = func.srcName;
		ofunc.blocks = new ArrayList<>();
		ofunc.architecture = architecture;
		ofunc.codeSize = func.blocks.stream().mapToLong(blk -> blk.asmLines().size()).sum();
		func.blocks.forEach(blk -> ofunc.blockIds.add(blk.id));
		func.blocks.forEach(blk -> {
			Block oblk = new Block();
			oblk.blockName = blk.name;
			oblk.binaryId = this.hash;
			oblk.binaryName = this.name;
			oblk.blockId = blk.id;
			oblk.callingBlocks = blk.call;
			oblk.codes = new ArrayList<>(blk.asmLines());
			oblk.oprTypes = new ArrayList<>(blk.oprTypes);
			oblk.codesSize = oblk.codes.size();
			oblk.funcCodeSize = ofunc.codeSize;
			oblk.functionId = func.id;
			oblk.functionName = func.name;
			oblk.peerSize = func.getNumberOfBlocks();
			oblk.bytes = StringResources.converteByteString(blk.bytes);
			oblk.sea = blk.sea;
			oblk.dat = blk.dat;
			oblk.architecture = architecture;
			ofunc.blocks.add(oblk);
		});

		ofunc.numBlocks = ofunc.blocks.size();
		ofunc.comments = func.comments.stream().map(cmm -> {
			return new Comment(func.id, cmm.comment, cmm.type, new Date().getTime(), "user_ida", cmm.offset);
		}).collect(Collectors.toList());
		return ofunc;
	}

	public List<Function> toFunctions() {
		return this.functions //
				.stream() //
				.map(this::toFunction) //
				.collect(Collectors.toList());
	}

	public String toJson(boolean pretty) throws Exception {
		if (!pretty) {
			ObjectMapper mapper = new ObjectMapper();
			return mapper.writeValueAsString(this);
		} else {
			ObjectMapper mapper = new ObjectMapper();
			return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(this);
		}
	}

	public void sort() {
		// sorting according to the memory address
		// keep the block in order
		Ranker<FunctionSurrogate> functionHeap = new Ranker<FunctionSurrogate>();
		for (FunctionSurrogate function : this.functions) {
			functionHeap.push(function.id, function);
		}
		this.functions = functionHeap.sortedList(true);
		functionHeap.clear();

		for (FunctionSurrogate function : this.functions) {
			Ranker<BlockSurrogate> blockHeap = new Ranker<BlockSurrogate>();
			for (BlockSurrogate block : function.blocks) {
				blockHeap.push(block.id, block);
			}
			function.blocks = blockHeap.sortedList(true);
		}
	}

	public BinarySurrogate processRawBinarySurrogate() {
		// generating IDs.
		if (this.md5.length() > 0)
			this.hash = HashUtils.constructID(this.md5.getBytes());
		else
			this.hash = HashUtils.constructID(this.name.getBytes()); // for backward compatibility

		TLongLongHashMap functionOldId2NewID = new TLongLongHashMap();
		for (FunctionSurrogate function : this.functions) {
			Long fnewId = HashUtils.constructID(DmasByteOperation.getBytes(this.hash),
					DmasByteOperation.getBytes(function.id));
			functionOldId2NewID.put(function.id, fnewId);

			TLongLongHashMap blockOldId2NewID = new TLongLongHashMap();
			for (BlockSurrogate block : function.blocks) {
				blockOldId2NewID.put(block.id, HashUtils.constructID(DmasByteOperation.getBytes(fnewId),
						DmasByteOperation.getBytes(block.id)));
			}
			// set new id for block's calling blocks
			for (BlockSurrogate block : function.blocks) {
				block.id = blockOldId2NewID.get(block.id);
				for (int i = 0; i < block.call.size(); ++i)
					block.call.set(i, blockOldId2NewID.get(block.call.get(i)));
				Collections.sort(block.call);
			}
		}
		// set new id for function's calling functions
		for (FunctionSurrogate function : this.functions) {
			function.id = functionOldId2NewID.get(function.id);
			for (int i = 0; i < function.call.size(); ++i) {
				function.call.set(i, functionOldId2NewID.get(function.call.get(i)));
			}
		}
		return this;

	}

	/**
	 * parse json and generate appropriate id
	 * 
	 * @param json
	 * @return
	 * @throws Exception
	 */
	public static BinarySurrogate loadFromJson(String json) throws Exception {
		try {
			return mapper.readValue(json, BinarySurrogate.class);
		} catch (Exception e) {
			Charset charset = Charset.forName("UTF-8");
			json = charset.decode(charset.encode(json)).toString();
			return mapper.readValue(json, BinarySurrogate.class);
		}
	}

	public static BinarySurrogate load(File file) throws Exception {
		try {
			return mapper.readValue(file, BinarySurrogate.class);
		} catch (Exception e) {
			byte[] bytes = Files.readAllBytes(file.toPath());
			Charset charset = Charset.forName("UTF-8");
			String json = charset.decode(ByteBuffer.wrap(bytes)).toString();
			return mapper.readValue(json, BinarySurrogate.class);
		}
	}

	public static BinarySurrogate loadNoException(File file) {
		try {
			return load(file);
		} catch (Exception e) {
			logger.error("Failed to load binarysurrogate :" + file.getAbsolutePath(), e);
			return null;
		}
	}

	public static List<BinarySurrogate> loadAllFromFolder(String folder) {
		return DmasFileOperations.selectNoException(folder, DmasFileOperations.REGEX_JSON).stream()
				.map(f -> BinarySurrogate.loadNoException(f)).collect(Collectors.toList());
	}

	public static BinarySurrogate load(String filePath) throws Exception {
		return load(new File(DmasApplication.applyDataContext(filePath)));
	}

	public void writeNoExcept(File file) {
		try {
			mapper.writerWithDefaultPrettyPrinter().writeValue(file, this);
		} catch (Exception e) {
			logger.error("Failed to save binarysurrogate :" + file.getAbsolutePath(), e);
		}
	}

	public BinarySurrogateMultipart toMultipart() {
		return new BinarySurrogateMultipart(Arrays.asList(this), 1);
	}

	public static BinarySurrogate generateDummyInputForTesting() throws Exception {
		BinarySurrogate surrogate = new BinarySurrogate();
		surrogate.hash = "abcdefg".hashCode();
		surrogate.name = "abcdefg.exe";

		FunctionSurrogate function1 = new FunctionSurrogate();
		function1.name = "function1";
		function1.id = 40001;

		FunctionSurrogate function2 = new FunctionSurrogate();
		function2.name = "function2";
		function2.id = 40003;

		FunctionSurrogate function3 = new FunctionSurrogate();
		function3.name = "function3";
		function3.id = 40002;

		FunctionSurrogate function4 = new FunctionSurrogate();
		function4.name = "function4";
		function4.id = 40005;

		function1.call.add(function2.id);
		function1.call.add(function4.id);
		function2.call.add(function3.id);
		function2.call.add(function4.id);
		function3.call.add(function1.id);

		surrogate.functions.add(function1);
		surrogate.functions.add(function2);
		surrogate.functions.add(function3);
		surrogate.functions.add(function4);

		BlockSurrogate b1 = new BlockSurrogate();
		b1.sea = 40006;
		b1.eea = 40018;
		b1.src = new ArrayList<>(Arrays.asList(Arrays.asList("some", "code")));
		b1.id = 1;

		BlockSurrogate b2 = new BlockSurrogate();
		b2.sea = 40019;
		b2.eea = 40100;
		b2.src = new ArrayList<>(Arrays.asList(Arrays.asList("some", "code")));
		b2.id = 2;

		BlockSurrogate b3 = new BlockSurrogate();
		b3.sea = 40101;
		b3.eea = 40108;
		b3.src = new ArrayList<>(Arrays.asList(Arrays.asList("some", "code")));
		b3.id = 3;

		b1.call.add(b2.id);
		b1.call.add(b3.id);
		b2.call.add(b1.id);

		function4.blocks.add(b1);
		function4.blocks.add(b2);
		function4.blocks.add(b3);

		return loadFromJson(surrogate.toJson(true));
	}

	public static void main(String[] args) throws Exception {
		System.out.println(loadFromJson(generateDummyInputForTesting().toJson(true)).toJson(true));
	}

}
