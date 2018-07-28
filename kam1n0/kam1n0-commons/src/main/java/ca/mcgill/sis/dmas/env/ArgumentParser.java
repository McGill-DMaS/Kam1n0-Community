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
package ca.mcgill.sis.dmas.env;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Joiner;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;

public class ArgumentParser {

	public static final Object NOTHING = new Object();

	public static enum OpType {
		Integer, Double, File, Directory, String, Boolean
	}

	private static Object newInstance(OpType type, String value, String[] validValues) throws Exception {
		switch (type) {
		case Integer:
			return Integer.parseInt(value);
		case Double:
			return Double.parseDouble(value);
		case File:
			File file = new File(DmasApplication.applyDataContext(value));
			return file;
		case Directory:
			File dir = new File(DmasApplication.applyDataContext(value));
			return dir;
		case String:
			if (validValues == null)
				return value;
			else {
				for (String validValue : validValues) {
					if (validValue.equalsIgnoreCase(value))
						return value;
				}
				throw new Exception("Unsupported value [" + value + "].");
			}

		case Boolean:
			return Boolean.parseBoolean(value);
		default:
			throw new Exception("Does not support the input option type:" + type.toString());
		}
	}

	public class Option {
		public String name;
		public OpType type;
		public String description;
		public boolean multiValue;
		public Object defaultValue = null;
		public String[] validValues = null;

		@SuppressWarnings("unchecked")
		public <T> T getValue() throws Exception {
			if (multiValue) {
				List<Object> list = values.get(name);
				if (list.size() < 1 && defaultValue != null)
					list.add(defaultValue);
				return (T) list;
			} else {
				List<Object> ls = values.get(name);
				if (ls.size() > 1) {
					logger.warn("The input for option \"{}\" has more than on values: {}; Picking the first one.", name,
							ls.toString());
				} else if (ls.size() < 1) {
					if (defaultValue == null) {
						logError("No value has been specified for option \"" + name + "\"");
						throw new Exception("Did not provide enough parameters. ");
					} else {
						return (T) defaultValue;
					}
				}
				return (T) ls.get(0);
			}
		}
	}

	private String mode = StringResources.STR_EMPTY;

	private static Logger logger = LoggerFactory.getLogger(ArgumentParser.class);

	private ListMultimap<String, Object> values = ArrayListMultimap.create();
	private HashMap<String, Option> options = new HashMap<>();

	public Option addOption(String name, OpType type, boolean multiValue, String description) {
		Option option = new Option();
		option.name = name;
		option.type = type;
		option.multiValue = multiValue;
		option.description = description;
		options.put(option.name, option);
		return option;
	}

	public Option addOption(String name, OpType type, boolean multiValue, String description, Object defaultValue) {
		Option option = new Option();
		option.name = name;
		option.type = type;
		option.multiValue = multiValue;
		option.description = description;
		options.put(option.name, option);
		option.defaultValue = defaultValue;
		return option;
	}

	public Option addSelectiveOption(String name, boolean multiValue, String description, String defaultValue,
			String... validValues) {
		Option option = new Option();
		option.name = name;
		option.type = OpType.String;
		option.multiValue = multiValue;
		option.description = description;
		options.put(option.name, option);
		option.defaultValue = defaultValue;
		option.validValues = validValues;
		return option;
	}

	public Option addSelectiveOption(String name, boolean multiValue, String description, String defaultValue,
			List<String> validValues) {
		Option option = new Option();
		option.name = name;
		option.type = OpType.String;
		option.multiValue = multiValue;
		option.description = description;
		options.put(option.name, option);
		option.defaultValue = defaultValue;
		option.validValues = validValues.toArray(new String[validValues.size()]);
		return option;
	}

	public static ArgumentParser create(String mode) {
		return new ArgumentParser(mode);
	}

	private ArgumentParser(String mode) {
		this.mode = mode;
	}

	public boolean parse(String[] args) {
		try {
			for (String string : args) {

				if (string.equals("-help")) {
					printOptions();
					return false;
				}

				if (!string.startsWith("-") || !string.contains("=")) {
					logError("Invalid input format: " + string);
					return false;
				}

				String[] q = string.substring(1).split("=");
				if (q.length != 2) {
					logError("Invalid input format: " + string);
					return false;
				}
				Option vs = options.get(q[0]);
				if (vs == null) {
					logError("Invalid input option: " + q[0]);
					return false;
				}
				Object v = newInstance(vs.type, q[1], vs.validValues);
				values.get(q[0]).add(v);
			}
			return true;
		} catch (Exception e) {
			logger.error("Failed to parse the arguments.", e);
			logError("Error in parsing arguments.");
			return false;
		}

	}

	public void logError(String msg) {
		logger.error("Error input; {}", msg);
		printOptions();
	}

	public void printOptions() {
		StringResources.print("- - - - - - - - - - - - - - - - - - - - - -");
		StringResources.print("Options for the mode {}:", mode);
		for (Entry<String, Option> option : options.entrySet()) {
			StringResources.print(String.format("| -%-30s %-10s %-4s %-100s", option.getKey(),
					"[" + option.getValue().type.toString() + "]", option.getValue().multiValue ? "[m]" : "[s]",
					option.getValue().description));
			if (option.getValue().validValues != null) {
				StringResources.print(String.format("| %-47s (valid values:[%s])", "",
						Joiner.on("\\").join(option.getValue().validValues)));
			}
			if (option.getValue().defaultValue != null) {
				StringResources
						.print(String.format("| %-47s (default=%s)", "", option.getValue().defaultValue.toString()));
			}
		}
		printFormat();
	}

	public void printFormat() {
		StringResources.print("- - - - - - - - - - - - - - - - - - - - - -");
		StringResources.print("| Option name should format as \"%Option_Name%=%Option_Value1%\"");
		StringResources.print("| Single-value options are denoted by flag [s].");
		StringResources.print(
				"| For multi-value options (denoted by [m]): \"%Option_Name%=%Option_Value1%\" \"%Option_Name%=%Option_Value2%\"");
		StringResources.print("- - - - - - - - - - - - - - - - - - - - - -");
		return;
	}

	public static void main(String[] args) throws Exception {
		ArgumentParser parser = ArgumentParser.create("test");
		Option option = parser.addOption("int1", OpType.Integer, false, "an integer value");
		parser.parse(new String[] { "-int1=asdf" });
		Integer values = option.getValue();
		logger.info(values.toString());
	}

}
