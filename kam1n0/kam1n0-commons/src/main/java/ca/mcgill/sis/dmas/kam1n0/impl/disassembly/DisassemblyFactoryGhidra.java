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
package ca.mcgill.sis.dmas.kam1n0.impl.disassembly;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;

public class DisassemblyFactoryGhidra extends DisassemblyFactory {

	private static Logger logger = LoggerFactory.getLogger(DisassemblyFactory.class);

	public final static String JDK13_LINUX = "https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-13.0.1_linux-x64_bin.tar.gz";
	public final static String JDK13_WINDOWS = "https://download.java.net/java/GA/jdk13.0.1/cec27d702aa74d5a8630c65ae61e4305/9/GPL/openjdk-13.0.1_windows-x64_bin.zip";
	public final static String Ghidra_JAR = "https://github.com/L1NNA/JARV1S-Ghidra/releases/download/v0.0.1/jarv1s-ghidra.jar";

	// use user home folder instead to avoid permission issues
	private static File installationDirectory = new File(new File(System.getProperty("user.home")), ".kam1n0-ghidra");

	public static void unZip(File zipped, File destination) throws IOException {
		String destDirPath = destination.getCanonicalPath();
		ZipInputStream zis = new ZipInputStream(new FileInputStream(zipped));
		ZipEntry zipEntry = zis.getNextEntry();
		while (zipEntry != null) {
			File newFile = new File(destination, zipEntry.getName());
			// check for the zip slip attack
			if (!newFile.getCanonicalPath().startsWith(destDirPath + File.separator)) {
				throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
			}
			if (!zipEntry.isDirectory()) {
				// copy file
				newFile.getParentFile().mkdirs();
				IOUtils.copy(zis, new FileOutputStream(newFile));
			}
			zipEntry = zis.getNextEntry();
		}
		zis.closeEntry();
		zis.close();
	}

	public static void unTarGzip(File tarGzip, File destination) throws IOException {
		String destDirPath = destination.getCanonicalPath();
		TarArchiveInputStream tis = null;
		try {
			FileInputStream fis = new FileInputStream(tarGzip);
			GZIPInputStream gzipInputStream = new GZIPInputStream(new BufferedInputStream(fis));
			tis = new TarArchiveInputStream(gzipInputStream);
			TarArchiveEntry tarEntry = null;
			while ((tarEntry = tis.getNextTarEntry()) != null) {
				if (tarEntry.isDirectory()) {
					continue;
				} else {
					// check for the zip slip attack
					File newFile = new File(destination, tarEntry.getName());
					if (!newFile.getCanonicalPath().startsWith(destDirPath + File.separator)) {
						throw new IOException("Entry is outside of the target dir: " + tarEntry.getName());
					}
					// copy file
					newFile.getParentFile().mkdirs();
					IOUtils.copy(tis, new FileOutputStream(newFile));
				}
			}
		} catch (IOException ex) {
			logger.error("Error while untarring. ", ex);
		} finally {
			if (tis != null) {
				tis.close();
			}
		}
	}

	public static File downloadAndExtract(String link) throws Exception {

		String fileName = Paths.get(new URI(link).getPath()).getFileName().toString();
		File downloaded = new File(installationDirectory, fileName);
		File folder = new File(downloaded.getPath().substring(0, downloaded.getPath().lastIndexOf(".")));

		if (!downloaded.exists()) {
			FileUtils.copyURLToFile(new URL(link), downloaded);
			logger.info("Downloading {} to {}", link, downloaded.getAbsolutePath());
		}

		if (downloaded.getName().endsWith(".zip")) {
			if (!folder.exists())
				unZip(downloaded, folder);
			return folder;
		} else if (downloaded.getName().endsWith(".tar.gzip")) {
			if (!folder.exists())
				unTarGzip(downloaded, folder);
			return folder;
		}
		return downloaded;
	}

	public static File installJDK13() throws Exception {
		String url = JDK13_LINUX;
		String path = "jdk-13.0.1/bin/java";
		String OS = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
		if ((OS.indexOf("mac") >= 0) || (OS.indexOf("darwin") >= 0)) {
			logger.error("Not supported for MAC yet.");
		} else if (OS.indexOf("win") >= 0) {
			url = JDK13_WINDOWS;
			path = path + ".exe";
		} else if (OS.indexOf("nux") >= 0) {
			url = JDK13_LINUX;
		} else {
			logger.error("unknow operation system.");
		}
		File folder = downloadAndExtract(url);
		return new File(folder, path).getAbsoluteFile();
	}

	public static File installGhidraJar() throws Exception {
		return downloadAndExtract(Ghidra_JAR);
	}

	private File java;
	private File jar;

	public DisassemblyFactoryGhidra() throws Exception {

	}

	@Override
	public void init() {
		if (!installationDirectory.exists())
			installationDirectory.mkdirs();
		try {
			this.java = installJDK13();
			this.jar = installGhidraJar();
			if (!this.java.exists())
				logger.error("Failed to install/find JDK13 for Ghidra: {}", this.java.getCanonicalPath());
			else if (!this.jar.exists())
				logger.error("Failed to install/find Ghidra JAR at {}", this.jar.getCanonicalPath());
			else
				logger.info("Using {} for Ghidra JAR {}", this.java.getCanonicalPath(), this.jar.getCanonicalPath());
		} catch (Exception e) {
			logger.error("Failed to install Ghidra disassembler.", e);
		}

	}

	@Override
	public void close() {

	}

	public List<File> selectOutputFiles(String binaryPath) throws IOException {
		File binary = new File(binaryPath);
		File js = new File(binary.getCanonicalPath() + ".json");
		if (js.exists())
			return Arrays.asList(js);
		else
			return null;
	}

	@Override
	public BinarySurrogateMultipart loadAsMultiPart(String binaryPath, String name, int batchSize, boolean rebase,
			boolean cleanStack) throws Exception {

		try {

			List<File> parts = this.selectOutputFiles(binaryPath);
			String[] arg = null;
			if (parts == null || parts.size() < 1) {
				logger.info("Binary surrogate. Not found for {}", binaryPath);
				File ghidraProject = new File(binaryPath.substring(0, binaryPath.lastIndexOf(".")));
				ghidraProject.mkdirs();
				arg = new String[] { //
						this.java.getCanonicalPath(), //
						"-jar", //
						this.jar.getCanonicalPath(), //
						binaryPath, //
						binaryPath + ".json", //
						ghidraProject.getCanonicalPath(), //
						"false" };
				System.out.println(StringResources.JOINER_TOKEN.join(arg));

				ProcessBuilder pBuilder = new ProcessBuilder().inheritIO().command(arg);
				pBuilder.directory(this.java.getParentFile());
				Process p = pBuilder.start();
				p.waitFor();
				parts = this.selectOutputFiles(binaryPath);
				DmasFileOperations.deleteRecursively(ghidraProject.getAbsolutePath());
			} else {
				logger.info("Found existing binary surrogate. Skip disassembling for {}", binaryPath);
			}

			if (parts == null || parts.size() < 1) {
				logger.error("Failed to parse the assembly file. The output file parts cannot be located.");
				throw new Exception("Failed to disasemble the given file.");
			}

			// clean(binaryPath);
			List<File> newParts = parts;
			Iterable<BinarySurrogate> surrogateParts = () -> new Iterator<BinarySurrogate>() {

				Iterator<File> ite = newParts.iterator();

				@Override
				public boolean hasNext() {
					return this.ite.hasNext();
				}

				@Override
				public BinarySurrogate next() {
					BinarySurrogate binarySurrogate;
					try {
						binarySurrogate = DisassemblyFactoryGhidraModel.load(ite.next());
						binarySurrogate.name = name;
						binarySurrogate.processRawBinarySurrogate();
						return binarySurrogate;
					} catch (Exception e) {
						logger.error("Failed to parse the output json file.", e);
						return null;
					}

				}
			};

			return new BinarySurrogateMultipart(surrogateParts, newParts.size());

		} catch (Exception e) {
			logger.error("Failed to parse the assembly file.", e);
			throw e;
		}
	}

	public static void main(String[] args) throws Exception {
		long start = System.currentTimeMillis();
		Environment.init();
//		System.setProperty("kam1n0.disassembler", "ghidra");

		HashMap<File, BinarySurrogate> bin = DisassemblyFactory.diassemble(Arrays.asList(new File("I:\\ms-apt")),
				Pattern.compile(".*"));
		System.out.print(bin.size());
		System.out.print(System.currentTimeMillis() - start);
	}

}