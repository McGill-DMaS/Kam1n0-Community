package ca.mcgill.sis.dmas.kam1n0.cli;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
public class BatchDataset {
    private static final Logger logger = LoggerFactory.getLogger(BatchDataset.class);

    public static class Entry {
        public static int UNKNOWN_INDEX = -1;

        public final int matrixIndex;	 // self index of Entry instance in dataset array or UNKNOWN_INDEX
        public final long binaryId;
        public final String binaryName;
        public final Path fileName;
        public final int functionCount;

        @JsonCreator
        public Entry(@JsonProperty("matrixIndex") int matrixIndex,
                     @JsonProperty("binaryId") long binaryId,
                     @JsonProperty("binaryName") String binaryName,
                     @JsonProperty("fileName") Path fileName,
                     @JsonProperty("functionCount") int functionCount) {
            this.matrixIndex = matrixIndex;
            this.binaryId = binaryId;
            this.binaryName = binaryName;
            this.fileName = fileName;
            this.functionCount = functionCount;
        }
    }

    private final List<Entry> entries;
    private final Architecture arch;
    private final boolean mergeFunctions;

    public BatchDataset(Path path, boolean mergeFunctions) throws Exception {
        this.mergeFunctions = mergeFunctions;
        Architecture[] firstArchitectureFound = {null};
        logger.info("creating a mapping between binary names and the data...");
        List<Entry> tempEntries = new ArrayList<>(Files.walk(path).filter(Files::isRegularFile).parallel().map(p -> {
            try {
                Binary b = loadAssembly(p, mergeFunctions);
                if (firstArchitectureFound[0] == null)
                    firstArchitectureFound[0] = b.architecture;
                return new Entry(Entry.UNKNOWN_INDEX, b.binaryId, b.binaryName, p, b.functions.size());
            } catch (Exception e) {
                logger.error("Failed to load " + p + ". File will be ignored", e);
                return null;
            }
            // filtering and de-duplication:
        }).filter(Objects::nonNull).collect(Collectors.toMap(e -> e.binaryId, e -> e, (e1, e2) -> e1)).values());

        // sorted based on names
        tempEntries.sort(Comparator.comparing(e -> e.binaryName));

        // assign self index
        entries = IntStream.range(0, tempEntries.size()).mapToObj(index -> {
            Entry entry = tempEntries.get(index);
            return new Entry(index, entry.binaryId, entry.binaryName, entry.fileName, entry.functionCount);
        }).collect(Collectors.toList());

        arch = firstArchitectureFound[0];
    }

    @JsonCreator
    private BatchDataset(@JsonProperty("entries") List<Entry> entries,
                         @JsonProperty("arch") Architecture arch,
                         @JsonProperty("mergeFunctions") boolean mergeFunctions) {
        this.entries = entries;
        this.arch = arch;
        this.mergeFunctions = mergeFunctions;
    }

    private static Binary loadAssembly(Path p, boolean mergeFunctions) throws Exception {
        BinarySurrogate b;
        File assemblyFile = p.toFile();

        if (assemblyFile.getName().endsWith(".json")) {
            b = BinarySurrogate.load(assemblyFile);
            b.processRawBinarySurrogate();
        } else {
            b = DisassemblyFactory.disassembleSingle(assemblyFile);
            if (mergeFunctions) {
                FunctionSurrogate fs = b.functions.get(0);
                fs.blocks = b.functions.stream().flatMap(f -> f.blocks.stream())
                        .collect(Collectors.toCollection(ArrayList::new));
                b.functions.clear();
                b.functions.add(fs);
            }
        }
        Binary bin = b.toBinary();
        bin.binaryName = assemblyFile.getName().split("\\.")[0] + '-' + b.md5.substring(0, 8);

        return bin;
    }

    /**
     * @return null if no entries
     */
    public Architecture getArchitecture() {
        return arch;
    }

    public List<Entry> getEntries() {
        return entries;
    }

    public int size() {
        return entries.size();
    }

    /**
     * Binaries in this dataset are single-part binaries, but are wrapped here into a list of BinaryMultiParts. The
     * wrapper allows for iterating the list (and getting its size) without having to load binaries. Those will be
     * loaded only when each BinaryMultiParts is iterated itself to extract its part (here the single binary part)
     * @return list of BinaryMultiParts each containing a lazily-loaded binary
     */
    public List<BinaryMultiParts> getAllBinariesAsMultiParts() {
        return entries.stream().map(entry -> {
            Iterable<Binary> singleBinaryIterable = () -> List.of(getBinary(entry.matrixIndex)).iterator();
            return new BinaryMultiParts(singleBinaryIterable, 1);
        }).collect(Collectors.toList());
    }

    public Binary getBinary(int entryIndex) {
        return getBinary(entryIndex, mergeFunctions);
    }

    public Binary getBinary(int entryIndex, boolean mergeFunctionsOverride) {
        Path filePath = entries.get(entryIndex).fileName;
        try {
            return loadAssembly(filePath, mergeFunctionsOverride);
        } catch( Exception e ) {
            throw new RuntimeException(MessageFormat.format(
                    "Binary {} could not be loaded. Should have been filtered out earlier while building the dataset",
                    filePath));
        }
    }
}
    
