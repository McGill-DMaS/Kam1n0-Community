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
import java.lang.reflect.Method;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.ArgumentParser.OpType;
import ca.mcgill.sis.dmas.env.ArgumentParser.Option;
import ca.mcgill.sis.dmas.kam1n0.cli.CLIFunction;

public class Exp extends CLIFunction {

	private ArgumentParser parser = ArgumentParser.create(Exp.class.getSimpleName());

	private Option op1 = parser.addOption("cls", OpType.String, false, "the full class name");

	private Option opArg = parser.addOption("arg", OpType.String, false,
			"the argument list as string (seperated by space)", "");

	@Override
	public ArgumentParser getParser() {
		return parser;
	}

	@Override
	public String getDescription() {
		return "run the main function of a specific class.";
	}

	@Override
	public String getCode() {
		return "exp";
	}

	@Override
	public void process(String[] args) throws Exception {
		parser.parse(args);
		String clName = op1.getValue();
		Class<?> cls = Class.forName(clName);
		Method meth = cls.getMethod("main", String[].class);
		String[] params = opArg.getValue().toString().split("\\S");
		meth.invoke(null, (Object) params);
	}

	@Override
	public String getCategory() {
		return "JAR utilities";
	}

}
