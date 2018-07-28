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
package ca.mcgill.sis.dmas.kam1n0.cli.dgen.processing;

import java.io.File;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.kam1n0.utils.src.AsmCloneMapper.Strategy;
import ca.mcgill.sis.dmas.kam1n0.utils.src.Parser.ParserType;

public class Configuration {

	private static Logger logger = LoggerFactory.getLogger(Configuration.class);

	@Deprecated
	public Configuration() {
	}

	public Configuration(String path) {
		this.selfFile = path;
	}

	public String sourceFunctionFile_suffix = "/srcFuncs.json";
	public String groundTruthFile_suffix = "/truth.json";
	public String asmFolder_suffix = "/asm/";
	public String selfFile = "conf.xml";

	@JsonIgnore
	public String getSrcFuncFileDir() {
		return new File(selfFile).getParentFile().getAbsolutePath() + this.sourceFunctionFile_suffix;
	}

	@JsonIgnore
	public String getGroundTruthFileDir() {
		return new File(selfFile).getParentFile().getAbsolutePath() + this.groundTruthFile_suffix;
	}

	@JsonIgnore
	public String getAsmFolderDir() {
		return new File(selfFile).getParentFile().getAbsolutePath() + this.asmFolder_suffix;
	}

	public boolean translateVex = false;

	public Strategy mappingStrategy = Strategy.mapBySrcClone;
	public ParserType srcParserType = ParserType.objdump;

	public Integer ccfinderx_t = 50;
	public Integer ccfinderx_b = 12;

	public ArrayList<SourceProject> projects = new ArrayList<>();

	public static class SourceProject {
		public String dir;
		public String SourceDirectoryWhenCompile;
		public String SourceDirectoryAfterCompile;
		public ArrayList<String> binaries = new ArrayList<>();
	}

	public void save(String file) {
		try {
			this.selfFile = file;
			(new ObjectMapper()).writerWithDefaultPrettyPrinter()
					.writeValue(new File(DmasApplication.applyDataContext(file)), this);
		} catch (Exception e) {
			logger.error("Failed to save object to file " + DmasApplication.applyDataContext(file), e);
		}
	}

	public void print() {
		try {
			System.out.println();
			System.out.println((new ObjectMapper()).writerWithDefaultPrettyPrinter().writeValueAsString(this));
		} catch (Exception e) {
			logger.error("Failed to print object.", e);
		}
	}

	public static Configuration load(String file) {
		try {
			File fl = new File(DmasApplication.applyDataContext(file));
			Configuration conf = (new ObjectMapper()).readValue(fl, Configuration.class);
			conf.selfFile = fl.getAbsolutePath();
			return conf;
		} catch (Exception e) {
			logger.error("Failed to load object from " + DmasApplication.applyDataContext(file), e);
			return null;
		}

	}

}
