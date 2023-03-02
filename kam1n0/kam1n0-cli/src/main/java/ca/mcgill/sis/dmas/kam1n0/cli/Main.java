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
package ca.mcgill.sis.dmas.kam1n0.cli;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;

import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.collect.HashMultimap;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class Main {

	public static HashMap<String, CLIFunction> operations = new HashMap<>();

	private static Logger logger = LoggerFactory.getLogger(Main.class);

	private static ArgumentParser parser = ArgumentParser.create("Main");

	private static void printBanner() {
		try {
			Lines lines = Lines.fromFile(KamResourceLoader.loadFile("kam1n0-banner.txt").getAbsolutePath(),
					Charsets.US_ASCII);
			if (KamResourceLoader.useAnsi)
				lines.forEach(line -> System.out.println(KamResourceLoader.colorHighlight(line)));
			else
				lines.forEach(System.out::println);
		} catch (Exception e) {
			logger.warn("Missing banner file.");
		}
	}

	private static void initOptions() {

		operations.clear();
		Reflections reflections = new Reflections("ca.mcgill.sis.dmas.kam1n0.cli");
		Set<Class<? extends CLIFunction>> allClasses = reflections.getSubTypesOf(CLIFunction.class);

		allClasses.forEach(cli -> {
			CLIFunction func;
			try {
				func = cli.newInstance();
				operations.put("--" + func.getCode(), func);
			} catch (Exception e) {
				logger.error("Failed to init class " + cli.getName(), e);
			}
		});

	}

	private static void printOptions() {
		HashMultimap<String, CLIFunction> categoryMap = HashMultimap.create();

		System.out.println("Operations:");
		System.out.println();

		operations.forEach((k, v) -> categoryMap.put(v.getCategory(), v));

		categoryMap.keySet().forEach(k -> {
			StringResources.print("Category: {}", k);
			categoryMap.get(k).forEach(v -> StringResources.print("| --{} \t\t {}.", v.getCode(), v.getDescription()));
		});

		parser.printFormat();
	}

	public static void main(String[] args) throws Exception {

		Environment.init();
		initOptions();
		System.setSecurityManager(null);
		if (args.length < 1) {
			printBanner();
			printOptions();
			return;
		}

		if (args[0].equalsIgnoreCase("--help")) {
			printOptions();
			return;
		}

		CLIFunction operation;
		operation = operations.get(args[0]);
		if (operation == null) {
			logger.error("Invalid operation: {}", args[0]);
			printOptions();
			logger.info("Exiting.");
			return;
		}
		operation.process(Arrays.copyOfRange(args, 1, args.length));
		logger.info("Exiting.");
	}

}
