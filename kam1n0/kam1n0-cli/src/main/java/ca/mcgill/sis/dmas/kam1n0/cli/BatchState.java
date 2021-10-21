package ca.mcgill.sis.dmas.kam1n0.cli;

import ca.mcgill.sis.dmas.env.DmasApplication;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Batch state, can be persisted to allow for resuming an interrupted batch.
 *  - Resumable feature through persistence is optional: must be specified at instance creation, through static
 *    BatchState.createOrResume()
 *  - Although closely tied to the batch process to maintain its state, it does not contain only batch process logic
 *
 * On a 'resumable' batch, state is saved on each checkpoint, upon explicit caller notification:
 *  - notifyDatasetCreated() : once, to provide dataset
 *  - notifyIndexingDone() : once. indexing data is NOT stored in BatchState, external database is assumed (caller is
 *                           responsible to reconnect to it when resuming a batch)
 *  - notifyFileProcessed() : once for each file processed.
 *  - notifyCompleted() : when all files are processed, this deletes the saved state file.
 * State is saved in a JSON file in the current working folder (at the moment the BatchState is first created).
 * JSON file is expected to be found there as well when resuming an interrupted batch. It is deleted once the batch
 * is completed.
 *
 * Above notifications must be called in that order, whether resumable or not, although a batch can be 'completed' at
 * any time.
 *
 * This class is overall NOT thread-safe, except for notifyFileProcessed() that can handle multiple threads pushing
 * results in parallel. Other notifications are meant to be sequential
 */
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
public class BatchState {
    private static final Logger logger = LoggerFactory.getLogger(BatchState.class);

    public enum Stage {
        CREATE_INSTANCE,
        CREATE_DATASET,
        INDEX_FILES,
        // Note: no "process_files" stage: would never be used since we only consider the last completed stage, and
        //       this would only occur on notifyCompleted() after which the BatchState instance is not relevant anymore.
    }

    private static final String PERSISTENT_DATA_FILENAME = "batch_state.json";
    private static final String BACKUP_EXTENSION = ".bkp";

    private transient Path serializedFileName;
    private Stage lastCompletedStage;

    private BatchDataset dataset;        // null is "no dataset yet"
    private boolean[] isFileProcessed;   // index is dataset entry index, null if no dataset
    private double[][] similarityMatrix; // [target][source] indices are dataset entry indices, null if no dataset

    public static BatchState createOrResume(boolean allowResume) throws Exception {
        BatchState batch;
        Path expectedFileName = Paths.get(DmasApplication.applyDataContext(PERSISTENT_DATA_FILENAME));
        Path expectedBackupFileName = generateBackupFileName(expectedFileName);

        if (allowResume && (Files.exists(expectedFileName) || Files.exists(expectedBackupFileName))) {
            logger.info("Resuming interrupted batch from {}.", expectedFileName);
            batch = deserialize(expectedFileName, expectedBackupFileName);
            logger.info("Left to do: ");
            boolean hasDataset = batch.getLastCompletedStage().compareTo(Stage.CREATE_DATASET) >= 0;
            switch (batch.getLastCompletedStage()) {
                case CREATE_INSTANCE:
                    logger.info(" - create dataset from input binaries");    // fallthrough
                case CREATE_DATASET:
                    logger.info(" - index binaries"); // fallthrough
                case INDEX_FILES:
                    if (hasDataset) {
                        List<Integer> toDo = batch.getFilesToProcess();
                        final List<BatchDataset.Entry> entries = batch.dataset.getEntries();
                        int functionsToDo = toDo.stream().mapToInt(index -> entries.get(index).functionCount).sum();
                        logger.info(" - process {} binary file(s) ({} functions).", toDo.size(), functionsToDo);
                    } else {
                        logger.info(" - process all binaries and their functions.");
                    }
                    break;
                default:
                    throw new IllegalArgumentException(MessageFormat.format("Unhandled batch stage {}", batch.getLastCompletedStage()));
            }
        } else {
            if (allowResume) {
                logger.info("Creating resumable batch. State will be saved in {}.", expectedFileName);
            } else {
                logger.info("Executing non-resumable batch.");
                expectedFileName = null;
            }
            batch = new BatchState(expectedFileName);
        }
        return batch;
    }

    /**
     * Private constructor. BatchState instances are meant to be created only via BatchState.createOrResume()
     * @param persistentDataFile set to null for non-resumable batch (state won't be persisted)
     * @throws Exception any exception arising from writing initial state to persistentDataFile
     */
    private BatchState(Path persistentDataFile) throws Exception {
        this.serializedFileName = persistentDataFile == null ? null : persistentDataFile.toAbsolutePath();
        commit(Stage.CREATE_INSTANCE);
    }

    @JsonCreator
    private BatchState(@JsonProperty("lastCompletedStage") Stage lastCompletedStage,
                       @JsonProperty("dataset") BatchDataset dataset,
                       @JsonProperty("isFileProcessed") boolean[] isFileProcessed,
                       @JsonProperty("similarityMatrix") double[][] similarityMatrix) {
        this.lastCompletedStage = lastCompletedStage;
        this.dataset = dataset;
        this.isFileProcessed = isFileProcessed;
        this.similarityMatrix = similarityMatrix;
    }

    public Stage getLastCompletedStage() {
        return lastCompletedStage;
    }

    public void notifyDatasetCreated(BatchDataset dataset) throws Exception {
        assertStage(Stage.CREATE_INSTANCE, "Invalid batch stage", "BatchDataset already created.");

        this.dataset = dataset;
        // reset all related data
        similarityMatrix = new double[dataset.size()][dataset.size()];
        for (double[] row : similarityMatrix)
            Arrays.fill(row, 0.0);
        isFileProcessed = new boolean[dataset.size()];

        commit(Stage.CREATE_DATASET);
    }

    public BatchDataset getDataset() {
        return dataset;
    }

    // Note: no data is kept in BatchState about indexing stage. It is assumed to be in an external database that the
    // batch process can connect to when resuming an interrupted batch.
    public void notifyIndexingDone() throws Exception {
        assertStage(Stage.CREATE_DATASET, "Can't completed indexing before dataset is created",
                "Indexing was already completed");

        commit(Stage.INDEX_FILES);
    }

    public List<Integer> getAlreadyDoneFiles() {
        return isFileProcessed == null ? new ArrayList<>() :
                IntStream.range(0, isFileProcessed.length).filter(index -> isFileProcessed[index]).boxed().collect(Collectors.toList());
    }

    public List<Integer> getFilesToProcess() {
        return isFileProcessed == null ? new ArrayList<>() :
                IntStream.range(0, isFileProcessed.length).filter(index -> !isFileProcessed[index]).boxed().collect(Collectors.toList());
    }

    public void notifyFileProcessed(int fileIndex, double[] similarityResult) throws Exception {
        assertStage(Stage.INDEX_FILES, "May only push file results once indexing is completed",
                "Invalid batch state");

        // replace the full row in the matrix
        similarityMatrix[fileIndex] = similarityResult;
        isFileProcessed[fileIndex] = true;
        commit(lastCompletedStage);    // stage does not change
    }

    public double[][] getSimilarityMatrix() {
        return similarityMatrix;
    }

    public void notifyCompleted() {
        if (serializedFileName != null) {
            logger.info("Batch completed. Removing temporary state file {}.", serializedFileName);
            try {
                Files.delete(serializedFileName);
            } catch (IOException e) {
                logger.error("File could not be removed. You may want to delete it manually before starting a new batch.", e);
            }
        }
    }

    private void assertStage(Stage expectedCurrentStage, String errorMessageTooSoon, String errorMessageTooLate) {
        int stageComparison = lastCompletedStage.compareTo(expectedCurrentStage);
        if (stageComparison != 0) {
            String errorMessage = stageComparison < 0 ?  errorMessageTooSoon : errorMessageTooLate;
            throw new IllegalStateException(MessageFormat.format(
                    "{}. Last completed stage: {}", errorMessage, lastCompletedStage));
        }
    }

    private static Path generateBackupFileName(Path originalFileName) {
        return Paths.get(originalFileName + BACKUP_EXTENSION);
    }

    private static BatchState deserialize(Path fileName, Path backupFileName) throws Exception {
        BatchState batch = null;
        if (Files.exists(fileName)) {
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                batch = objectMapper.readValue(fileName.toFile(), BatchState.class);

                // just in case there was a previous interruption when both file existed
                Files.deleteIfExists(backupFileName);
            } catch (Exception e) {
                if (Files.exists(backupFileName)) {
                    logger.warn("Unable to read file (see error below), will try with backup file instead.", e);
                } else {
                    logger.error("Unable to read file", e);
                    throw e;
                }
            }
        }
        if (batch == null) {
            logger.warn("Interrupted batch state not found or invalid, resuming from backup of previous state: {}.", backupFileName);
            Files.deleteIfExists(fileName);
            Files.move(backupFileName, fileName);
            ObjectMapper objectMapper = new ObjectMapper();
            batch = objectMapper.readValue(fileName.toFile(), BatchState.class);
        }
        batch.serializedFileName = fileName;
        return batch;
    }

    private void commit(Stage completedStage) throws Exception {
        this.lastCompletedStage = completedStage;

        if (serializedFileName != null) {
            Path backupFileName = generateBackupFileName(serializedFileName);
            boolean hasBackup = false;
            if (Files.exists(serializedFileName)) {   // does not exist on first call to commit()
                Files.move(serializedFileName, backupFileName);
                hasBackup = true;
            }

            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.writerWithDefaultPrettyPrinter().writeValue(serializedFileName.toFile(), this);
            } catch (Exception e) {
                logger.error("Could not write batch state to {}", serializedFileName);
                if (hasBackup) {
                    logger.error("Previous state can still be found in {}", backupFileName);
                }
                logger.error("Aborting batch.");
                throw e;
            }

            Files.deleteIfExists(backupFileName);
        }
    }

}
