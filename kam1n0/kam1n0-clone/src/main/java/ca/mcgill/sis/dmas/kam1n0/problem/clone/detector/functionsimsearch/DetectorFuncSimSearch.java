package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.functionsimsearch;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.HttpsURLConnection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.Environment.KamMode;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.res.KamResourceLoader;
import net.lingala.zip4j.core.ZipFile;

public class DetectorFuncSimSearch extends FunctionCloneDetector {

	private static Logger logger = LoggerFactory.getLogger(DetectorFuncSimSearch.class);
	private final static String[] template = new String[] { "docker", "run", "-i", "--rm" };
	private static String entryPoint = "functionsimsearch";
	private final static String repo_url = "https://github.com/google/functionsimsearch/archive/master.zip";

	private Map<String, Function> storage = new HashMap<>();
	private Map<String, List<String>> cache = new HashMap<>();
	private Map<String, File> binaryFileLookupMap = new HashMap<>();

	public DetectorFuncSimSearch() {
	}

	public DetectorFuncSimSearch(String binarySearchPath) {
		binaryFileLookupMap = Arrays.asList(new File(binarySearchPath).listFiles()).stream()
				.collect(Collectors.toMap(file -> file.getName(), file -> file));
	}

	public static DetectorFuncSimSearch getDefault() {
		return new DetectorFuncSimSearch(System.getProperty("kam1n0.detector.functionsimsearch.binarypath"));
	}

	public File getBinaryFile(String binaryName) {
		File file = new File(binaryName);
		if (binaryName != null && binaryFileLookupMap.containsKey(file.getName()))
			return binaryFileLookupMap.get(file.getName());
		return file;
	}

	public static List<String> run_command_sync(boolean getOutput, String workingPath, String command, String... args) {
		List<String> cmd = new ArrayList<>(Arrays.asList(template));
		cmd.add("-v");
		cmd.add(new File(workingPath).getAbsolutePath() + ":/pwd");
		cmd.add(entryPoint);
		cmd.add(command);
		cmd.addAll(Arrays.asList(args));
		List<String> lines;
		try {
			ProcessBuilder pBuilder = new ProcessBuilder(cmd);
			if (!getOutput)
				pBuilder.inheritIO();
			System.out.println(StringResources.JOINER_TOKEN.join(cmd));
			Process p = pBuilder.start();
			p.waitFor();
			if (getOutput)
				lines = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8)).lines()
						.collect(Collectors.toList());
			else
				lines = new ArrayList<>();
			return lines;
		} catch (Exception e) {
			logger.error("Faield to execute command " + cmd, e);
			return new ArrayList<>();
		}
	}

	public static List<String> createIndex(File index) {
		ArrayList<String> outputs = new ArrayList<>();
		outputs.addAll(run_command_sync(false, index.getParentFile().getAbsolutePath(), "createfunctionindex",
				"--index=/pwd/" + index.getName()));
		return outputs;
	}

	public static void deleteIndex(File index) {
		index.delete();
	}

	public static List<String> addFileToIndex(File index, File file) {
		File weight = getWeights();
		List<String> cmd = new ArrayList<>(Arrays.asList(template));
		cmd.add("-v");
		cmd.add(file.getAbsolutePath() + ":/pwd/" + file.getName());
		cmd.add("-v");
		cmd.add(weight.getAbsolutePath() + ":/pwd/" + weight.getName());
		cmd.add("-v");
		cmd.add(index.getParentFile().getAbsolutePath() + ":/pwd/" + index.getParentFile().getName());
		cmd.add(entryPoint);
		cmd.add("addfunctionstoindex");
		cmd.add("-index=/pwd/" + index.getParentFile().getName() + "/" + index.getName());
		cmd.add("-weights=/pwd/" + weight.getName());
		cmd.add(file.getName().toLowerCase().endsWith(".dll") ? "-format=PE" : "-format=ELF");
		cmd.add("-input=/pwd/" + file.getName());
		cmd.add("-minimum_function_size=1");
		try {
			ProcessBuilder pBuilder = new ProcessBuilder(cmd);
			System.out.println(StringResources.JOINER_TOKEN.join(cmd));
			Process p = pBuilder.start();
			List<String> lines = new BufferedReader(
					new InputStreamReader(p.getInputStream(), StandardCharsets.US_ASCII)).lines()
							.collect(Collectors.toList());
			p.waitFor();
			return lines;
		} catch (Exception e) {
			logger.error("Faield to execute command " + cmd, e);
		}
		return new ArrayList<>();
	}

	public static List<String> scanFile(File index, File file) {
		File weight = getWeights();
		List<String> cmd = new ArrayList<>(Arrays.asList(template));
		cmd.add("-v");
		cmd.add(file.getAbsolutePath() + ":/pwd/" + file.getName());
		cmd.add("-v");
		cmd.add(weight.getAbsolutePath() + ":/pwd/" + weight.getName());
		cmd.add("-v");
		cmd.add(index.getParentFile().getAbsolutePath() + ":/pwd/" + index.getParentFile().getName());
		cmd.add(entryPoint);
		cmd.add("matchfunctionsfromindex");
		cmd.add("-index=/pwd/" + index.getParentFile().getName() + "/" + index.getName());
		cmd.add("-weights=/pwd/" + weight.getName());
		cmd.add(file.getName().toLowerCase().endsWith(".dll") ? "-format=PE" : "-format=ELF");
		cmd.add("-input=/pwd/" + file.getName());
		cmd.add("-minimum_function_size=1");
		try {
			ProcessBuilder pBuilder = new ProcessBuilder(cmd);
			System.out.println(StringResources.JOINER_TOKEN.join(cmd));
			Process p = pBuilder.start();
			List<String> lines = new BufferedReader(
					new InputStreamReader(p.getInputStream(), StandardCharsets.US_ASCII)).lines()
							.peek(System.out::println).collect(Collectors.toList());
			new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.US_ASCII)).lines()
					.collect(Collectors.toList()).forEach(System.out::printf);
			p.waitFor();

			return lines;
		} catch (Exception e) {
			logger.error("Faield to execute command " + cmd, e);
		}
		return new ArrayList<>();
	}

	public static File getWeights() {
		File weights = KamResourceLoader.getFileThatWillNotInDistribution("funcsimsearch_weights.txt");
		if (!weights.exists()) {
			String folder = Environment.getPlatformTmpDir("funcsimsearch");
			logger.info("Weight file not found. Downloading and training in " + folder);
			String zipFile = folder + "/src.zip";
			try {
				URL url = new URL(repo_url);
				HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
				try (InputStream stream = con.getInputStream()) {
					Files.copy(stream, Paths.get(zipFile));
				}
				ZipFile realZipFile = new ZipFile(zipFile);
				realZipFile.extractAll(folder);

				// the data path is /test_data/train_full;
				List<String> lines = run_command_sync(false, folder + "/functionsimsearch-master/testdata",
						"trainsimhashweights", "-data=/pwd/training", "-train_steps=5", "-weights=/pwd/weights.txt");

				lines.stream().forEach(System.out::println);
				String outputFile = folder + "/functionsimsearch-master/testdata/weights.txt";
				Files.copy(new File(outputFile).toPath(), weights.toPath());
			} catch (Exception e) {
				logger.error("Faided to train the weights given the data.", e);
			}
		}
		return weights;
	}

	private File indexFile;

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {

		// quick hack; we scan the file and cache all the results
		// since functionsimsearch only supports search the whole file.

		File target = getBinaryFile(function.binaryName);
		List<String> lines = null;
		synchronized (cache) {
			if (!cache.containsKey(function.binaryName))
				lines = scanFile(this.indexFile, target);
			else
				lines = cache.get(function.binaryName);
			cache.put(function.binaryName, lines);
		}

		Pattern resultFormat = Pattern
				.compile("\\) ([0-9.]+): ([a-z0-9]+)\\.([a-z0-9]+) matches ([a-z0-9]+)\\.([a-z0-9]+)");

		String src_pattern = "." + Long.toHexString(function.startingAddress).toLowerCase() + " matches ";
		return lines.stream().filter(line -> line.contains(src_pattern)).map(line -> {
			Matcher matcher = resultFormat.matcher(line);
			if (matcher.find()) {
				// logger.info("{}, {}, {}, {}", matcher.group(1), matcher.group(2),
				// matcher.group(3), matcher.group(4));
				String target_id = matcher.group(4) + "-" + matcher.group(5);
				double score = Double.parseDouble(matcher.group(1).trim());
				if (storage.containsKey(target_id)) {
					// logger.info("{} {} vs {}", StringResources.FORMAT_AR3D.format(score),
					// function.srcName,
					// storage.get(target_id).srcName);
					return new FunctionCloneEntry(storage.get(target_id), score);
				}
			}
			return null;
		}).filter(entry -> entry != null).filter(entry -> !avoidSameBinary || entry.binaryId != function.binaryId)
				.collect(Collectors.toList());
	}

	@Override
	protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binaries, LocalJobProgress progress)
			throws Exception {

		binaries.forEach(bin -> {
			File target = getBinaryFile(bin.binaryName);
			List<String> lines = addFileToIndex(this.indexFile, target);
			// lines.stream().forEach(logger::info);
			Optional<String> bid_line = lines.stream().filter(line -> line.startsWith("[!] Executable id is "))
					.findAny();
			// logger.info("---------------------------------");

			if (!bid_line.isPresent()) {
				logger.error("Failed indexing. Cannot find index id.");
				lines.forEach(line -> logger.info(line));
			} else {
				String bid = bid_line.get().replace("[!] Executable id is ", "").trim();
				bin.functions.stream().forEach(func -> {
					String identifier = bid + "-" + Long.toHexString(func.startingAddress);
					// logger.info(identifier);
					storage.put(identifier, func);
				});
			}
		});

	}

	@Override
	public String params() {
		return "";
	}

	@Override
	public void init() throws Exception {
		getWeights().getAbsolutePath();
		this.indexFile = new File(Environment.getPlatformTmpDir("test_repo") + "/tmp_index");
		if (this.indexFile.exists())
			this.indexFile.delete();
		createIndex(this.indexFile);
	}

	@Override
	public void close() throws Exception {
		if (this.indexFile.exists())
			this.indexFile.delete();
	}

	public static void main(String[] args) throws Exception {
		Environment.init(KamMode.server);
		getWeights();
		File target0 = new File(
				"E:/Compile-ICSE86/ds-all/asm/libz.so.1.2.11-gcc-g-O1-m32-fno-pic.bin.binaries.abbc965098b31645.json");
		File target1 = new File(
				"E:/Compile-ICSE86/ds-all/asm/libz.so.1.2.11-gcc-g-O3-m32-fno-pic.bin.binaries.89dd741655222126.json");
		Binary b0 = BinarySurrogate.load(target0).toBinary();
		Binary b1 = BinarySurrogate.load(target1).toBinary();

		DetectorFuncSimSearch detector = new DetectorFuncSimSearch("E:\\Compile-ICSE86\\ds-all\\binaries");
		detector.init();
		detector.indexFuncsToBeImplByChildren(-1, Arrays.asList(b0), new LocalJobProgress());
		for (Function func : b1.functions)
			detector.detectClonesForFuncToBeImpleByChildren(-1, func, -1, 10, false);
	}

}
