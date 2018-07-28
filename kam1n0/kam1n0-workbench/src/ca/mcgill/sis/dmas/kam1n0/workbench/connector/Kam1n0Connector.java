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
package ca.mcgill.sis.dmas.kam1n0.workbench.connector;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.workbench.controller.Console;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

public class Kam1n0Connector {

	private SimpleLogger logger;
	private Console console;
	private String KAM1N0_APP;
	public String KAM1N0_PROPERTIES_DEFAULT;

	public Kam1n0Connector(String kam1n0HomePath, SimpleLogger logger, Console console) {
		this.logger = logger;
		this.console = console;
		this.KAM1N0_APP = kam1n0HomePath + "/kam1n0-server.jar";
		if (new File(KAM1N0_APP).exists())
			logger.info("Found distribution kam1n0-server.jar");
		this.KAM1N0_PROPERTIES_DEFAULT = kam1n0HomePath + "/kam1n0.properties";
		if (new File(KAM1N0_PROPERTIES_DEFAULT).exists()) {
			KAM1N0_PROPERTIES_DEFAULT = new File(KAM1N0_PROPERTIES_DEFAULT).getAbsolutePath();
			logger.info("Found default configuration kam1n0.properties");
		}
	}

	Process running;

	public void startEngine(String propertyFile) {
		console.clear();
		logger.info("starting the engine...");
		new Thread(() -> {
			logger.info("starting the engine...");
			try {
				String jar = KAM1N0_APP;
				ArrayList<String> args = new ArrayList<>();
				args.add("java");
				ArrayList<String> jvmopts = getKamProperties(propertyFile);
				if (jvmopts != null)
					jvmopts.stream().filter(opt -> opt.startsWith("jvm-option"))
							.map(line -> line.substring(line.indexOf("=") + 1, line.length()).trim())
							.forEach(args::add);
				args.addAll(Arrays.asList(//
						"-Dkam1n0.ansi.enable=false", //
						"-jar", //
						jar, "--start"));
				logger.info("Calling:" + args.toString());
				ProcessBuilder pBuilder = new ProcessBuilder(args);
				running = pBuilder.start();
				inheritIO(running.getInputStream(), console);
				inheritIO(running.getErrorStream(), console);
				running.waitFor();
			} catch (Exception e) {
				logger.error("Failed to run the engine..." + e.getMessage());
			}
		}).start();

	}

	public ArrayList<String> getKamProperties(String file) {
		File jinit = new File(file);
		try {
			ArrayList<String> args = new ArrayList<>();
			if (jinit.isFile() && jinit.exists()) {
				List<String> confs = Files.readAllLines(jinit.toPath()).stream()
						.filter(line -> !line.trim().startsWith("#") && line.trim().length() > 0)
						.peek(line -> line.trim()).collect(Collectors.toList());
				args.addAll(confs);
			}
			return args;
		} catch (Exception e) {
			logger.error("Failed to load jvm options from:" + jinit.getAbsolutePath());
			return null;
		}
	}

	public ObservableList<PropertyBounding> getKamPropertyBoundings(String file) {
		return FXCollections.observableArrayList(getKamProperties(file).stream().map(arg -> {
			String[] vals = arg.split("=");
			PropertyBounding property = new PropertyBounding();
			property.key.set(vals[0]);
			if (vals.length > 1)
				property.value.set(String.join("=", Arrays.asList(vals).subList(1, vals.length)));
			return property;
		}).collect(Collectors.toList()));
	}

	public boolean setKamProperties(String file, String props) throws Exception {
		if (props != null) {
			File jinit = new File(file);
			Files.write(jinit.toPath(), props.getBytes(), StandardOpenOption.CREATE,
					StandardOpenOption.TRUNCATE_EXISTING);
		}
		return true;
	}

	public void stopEngine() {
		if (running != null) {
			running.destroy();
		}
	}

	private static void inheritIO(final InputStream src, final Consumer<String> printer) {
		new Thread(new Runnable() {
			public void run() {
				@SuppressWarnings("resource")
				Scanner sc = new Scanner(src);
				while (sc.hasNextLine()) {
					printer.accept(sc.nextLine());
				}
			}
		}).start();
	}

	// public Process browseCloneDataUnit(File file, Console newConsole) {
	// logger.info("Starting a new interface service for browsing data.");
	// try {
	// String jar = KAM1N0_APP;
	// ArrayList<String> args = new ArrayList<>();
	// args.add("java");
	// ArrayList<String> jvmopts = getKamProperties();
	// if (jvmopts != null)
	// jvmopts.stream().filter(opt -> opt.startsWith("jvm-option"))
	// .map(line -> line.substring(line.indexOf("=") + 1,
	// line.length()).trim()).forEach(args::add);
	// args.addAll(Arrays.asList("-jar", jar, "--brw-cmp", "-rf=" +
	// file.getAbsolutePath()));
	// logger.info("Calling:" + args.toString());
	// ProcessBuilder pBuilder = new ProcessBuilder(args);
	// Process newProcess = pBuilder.start();
	// PrintStream printer = new PrintStream(newConsole);
	// inheritIO(newProcess.getInputStream(), printer);
	// inheritIO(newProcess.getErrorStream(), printer);
	// addCLI(newProcess);
	// new Thread(() -> {
	// this.cleanCLI();
	// });
	// return newProcess;
	// } catch (Exception e) {
	// logger.error("Failed to run the engine..." + e.getMessage());
	// }
	// return null;
	// }

	LinkedList<Process> CLIs = new LinkedList<>();

	private synchronized void addCLI(Process p) {
		CLIs.add(p);
	}

	private synchronized void cleanCLI() {
		Iterator<Process> ite = CLIs.iterator();
		while (ite.hasNext()) {
			Process p = ite.next();
			if (p == null || !p.isAlive()) {
				ite.remove();
			}
		}
	}

	public void cleanup() {
		logger.info("Stopping running service.....");
		if (this.running != null && this.running.isAlive())
			this.running.destroyForcibly();
		CLIs.stream().filter(p -> p.isAlive()).forEach(Process::destroyForcibly);
	}

	public static class PropertyBounding {
		public SimpleStringProperty key = new SimpleStringProperty("property");
		public SimpleStringProperty value = new SimpleStringProperty("value");

		public String toLine() {
			return key.getValue() + "=" + value.getValue();
		}
	}

	public void setKamProperties(String file, ObservableList<PropertyBounding> items) throws Exception {
		String values = items.stream().filter(ite -> ite.key.getValue().trim().length() > 0).map(ite -> ite.toLine())
				.collect(Collectors.joining(System.lineSeparator()));
		setKamProperties(file, values);
	}
}
