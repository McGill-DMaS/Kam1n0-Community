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
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import com.thoughtworks.xstream.annotations.XStreamImplicit;
import com.thoughtworks.xstream.io.xml.DomDriver;

import ca.mcgill.sis.dmas.env.StringResources;

public class ArchitectureRepresentation {

	private static Logger logger = LoggerFactory.getLogger(ArchitectureRepresentation.class);

	public static class Register {
		@XStreamAsAttribute
		public String identifier = StringResources.STR_EMPTY;
		@XStreamAsAttribute
		public String category = StringResources.STR_EMPTY;
		@XStreamAsAttribute
		public int length = 8;

		public Register(String identifier, String category, int length) {
			this.identifier = identifier;
			this.category = category;
			this.length = length;
		}

		@Override
		public String toString() {
			return this.identifier;
		}
	}

	public static class Operation {
		@XStreamAsAttribute
		public String identifier = StringResources.STR_EMPTY;

		@XStreamImplicit(itemFieldName = "suffixGroup")
		public ArrayList<String> suffixGroups = new ArrayList<>();

		public Operation(String identifier) {
			this.identifier = identifier;
		}

		public Operation(String identifier, SuffixGroup... suffixGroups) {
			this.identifier = identifier;
			if (suffixGroups != null)
				Arrays.stream(suffixGroups).map(sg -> sg.identifier).forEach(this.suffixGroups::add);
		}

	}

	public static class SuffixGroup {

		@XStreamImplicit(itemFieldName = "suffix")
		public ArrayList<String> suffixs;

		@XStreamAsAttribute
		public String identifier = StringResources.STR_EMPTY;

		public SuffixGroup(String identifier, String... suffixs) {
			this.identifier = identifier;
			this.suffixs = new ArrayList<>(Arrays.asList(suffixs));
		}
	}

	public static class OprGroup {

		@XStreamAsAttribute
		public String identifier = StringResources.STR_EMPTY;

		@XStreamImplicit(itemFieldName = "opr")
		public ArrayList<String> oprs;

		public OprGroup(String identifier, String... oprs) {
			this.identifier = identifier;
			this.oprs = new ArrayList<>(Arrays.asList(oprs));
		}
	}

	public static class LineFormat {
		public String lineRegex = StringResources.STR_EMPTY;

		@XStreamAsAttribute
		public int numberOfOperand = 0;

		public LineFormat(String lineRegex, int numberOfOperand) {
			this.lineRegex = lineRegex;
			this.numberOfOperand = numberOfOperand;
		}
	}

	public static class LengthKeyWord {

		@XStreamAsAttribute
		public String identifier = StringResources.STR_EMPTY;

		@XStreamAsAttribute
		public int length = 8;

		public LengthKeyWord(String keyWord, int length) {
			this.identifier = keyWord;
			this.length = length;
		}
	}

	public enum KeyWordLocation {
		prefix, contains, suffix
	}

	public String processor = StringResources.STR_EMPTY;

	public ArrayList<Operation> operations = new ArrayList<>();
	public ArrayList<Operation> operationJmps = new ArrayList<>();
	public ArrayList<SuffixGroup> suffixGroups = new ArrayList<>();
	public ArrayList<OprGroup> oprGroups = new ArrayList<>();
	public ArrayList<Register> registers = new ArrayList<>();
	public ArrayList<LengthKeyWord> lengthKeywords = new ArrayList<>();
	public ArrayList<String> jmpKeywords = new ArrayList<>();
	public ArrayList<LineFormat> lineFormats = new ArrayList<>();

	public String constantVariableRegex = StringResources.STR_EMPTY;
	public String memoryVariableRegex = StringResources.STR_EMPTY;

	private static void setAlias(XStream xStream) {
		xStream.alias("Kam1n0-Architecture", ArchitectureRepresentation.class);
		xStream.alias("operation", Operation.class);
		xStream.alias("suffixGroup", SuffixGroup.class);
		xStream.alias("oprGroup", OprGroup.class);
		xStream.alias("lengthKeyWord", LengthKeyWord.class);
		xStream.alias("register", Register.class);
		xStream.alias("syntax", LineFormat.class);
		xStream.processAnnotations(ArchitectureRepresentation.class);
		xStream.processAnnotations(SuffixGroup.class);
		xStream.processAnnotations(OprGroup.class);
	}

	public static ArchitectureRepresentation load(File conf) {
		try {
			XStream xStream = new XStream(new DomDriver());
			xStream.setClassLoader(Thread.currentThread().getContextClassLoader());
			setAlias(xStream);
			ArchitectureRepresentation configuration = (ArchitectureRepresentation) xStream
					.fromXML(new FileReader(conf));
			return configuration;
		} catch (Exception e) {
			logger.error("Invalid format of configuration file. Please check your configuration file.", e);
		}
		return null;
	}

	public String toXml() {
		try {
			XStream xStream = new XStream(new DomDriver());
			setAlias(xStream);
			String xml = xStream.toXML(this);
			return xml;
		} catch (Exception e) {
			logger.error("Failed to save default configuration.", e);
		}
		return null;
	}

	// belows are helper functions to generate xml defnition.
	public void addOperation(String identifier, String... suffixes) {
		SuffixGroup suffixGroup = new SuffixGroup(identifier + "_g", suffixes);
		this.suffixGroups.add(suffixGroup);
		Operation opr = new Operation(identifier, suffixGroup);
		this.operations.add(opr);

	}

	public void addOprGroup(String identifier, String... oprs) {
		OprGroup oprGroup = new OprGroup(identifier, oprs);
		this.oprGroups.add(oprGroup);
	}

	public void addOperation(String identifier) {
		Operation opr = new Operation(identifier);
		this.operations.add(opr);

	}

	public void addJmpOperation(String identifier, String... suffixes) {
		SuffixGroup suffixGroup = new SuffixGroup(identifier + "_g", suffixes);
		this.suffixGroups.add(suffixGroup);
		Operation opr = new Operation(identifier, suffixGroup);
		this.operationJmps.add(opr);

	}

	public void addJmpOperation(String identifier) {
		Operation opr = new Operation(identifier);
		this.operationJmps.add(opr);

	}

}
