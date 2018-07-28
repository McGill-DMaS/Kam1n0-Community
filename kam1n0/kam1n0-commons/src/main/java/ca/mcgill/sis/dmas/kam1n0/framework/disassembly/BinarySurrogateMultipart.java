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
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BinarySurrogateMultipart implements Iterable<BinarySurrogate> {

	private static Logger logger = LoggerFactory.getLogger(BinarySurrogateMultipart.class);

	public final Iterable<BinarySurrogate> generatedIterable;
	public final int size;

	@Override
	public Iterator<BinarySurrogate> iterator() {
		return generatedIterable.iterator();
	}

	public BinarySurrogateMultipart(Iterable<BinarySurrogate> parts, int size) {
		this.generatedIterable = parts;
		this.size = size;
	}

	public static boolean check(File jsonFile) {
		try {
			BinarySurrogate.load(jsonFile);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public BinarySurrogateMultipart(File... jsonFile) {
		this.generatedIterable = () -> new Iterator<BinarySurrogate>() {

			Iterator<File> ite = Arrays.asList(jsonFile).iterator();

			@Override
			public boolean hasNext() {
				return this.ite.hasNext();
			}

			@Override
			public BinarySurrogate next() {
				BinarySurrogate binarySurrogate;
				try {
					binarySurrogate = BinarySurrogate.load(ite.next());
					return binarySurrogate;
				} catch (Exception e) {
					logger.error("Failed to parse the output json file.", e);
					return null;
				}

			}
		};
		this.size = jsonFile.length;
	}

	public BinarySurrogate merge() {
		List<BinarySurrogate> parts = StreamSupport.stream(generatedIterable.spliterator(), false)
				.collect(Collectors.toList());
		parts.stream().skip(1).forEach(part -> parts.get(0).functions.addAll(part.functions));
		return parts.get(0);
	}

	public Stream<BinarySurrogate> convertToStream() {
		return StreamSupport.stream(generatedIterable.spliterator(), false);
	}
}
