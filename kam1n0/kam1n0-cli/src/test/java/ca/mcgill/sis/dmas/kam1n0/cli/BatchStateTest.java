package ca.mcgill.sis.dmas.kam1n0.cli;

import static org.junit.Assert.*;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BatchStateTest {

    @Rule
    public TemporaryFolder tmpFolder = new TemporaryFolder();

    @Before
    public void setup() {
        DmasApplication.contextualize(tmpFolder.getRoot().getAbsolutePath());
    }

    @After
    public void teardown() {
        tmpFolder.delete();
    }

    private static final String[] entriesParts = {
            "\"binaryId\" : -7399422332982202115,\n      \"binaryName\" : \"file1-A0724D7A\",\n      \"fileName\" : \"abc/file1.bin.idb\",\n      \"functionCount\" : 1111",
            "\"binaryId\" : -1301922903993948580,\n      \"binaryName\" : \"file2-4FD013A7\",\n      \"fileName\" : \"abc/file2.bin.idb\",\n      \"functionCount\" : 2222",
            "\"binaryId\" : -6061535174955757996,\n      \"binaryName\" : \"file3-1F678620\",\n      \"fileName\" : \"abc/file3.bin.idb\",\n      \"functionCount\" : 777",
            "\"binaryId\" :  5751118332659467808,\n      \"binaryName\" : \"file4-F4569972\",\n      \"fileName\" : \"abc/file4.bin.idb\",\n      \"functionCount\" : 888",
    };
    private static final String[] architectures = {
            "\"type\" : \"metapc\",\n      \"size\" : \"b64\",\n      \"endian\" : \"le\"",
            "\"type\" : \"ppc\",   \n      \"size\" : \"b32\",\n      \"endian\" : \"be\"",
    };
    private static final double[] similarities = {
            0.6471926038, 0.1783548846, 0.7601535632, 0.8548779669, 0.5892629139, 0.6147528345, 0.2161659630
    };

    private static final String jsonFilename = "batch_state.json";
    private static final String jsonBackupFilename = "batch_state.json.bkp";

    private File getJsonFile() {
        return new File(tmpFolder.getRoot(), jsonFilename);
    }

    private File getJsonBackupFile() {
        return new File(tmpFolder.getRoot(), jsonBackupFilename);
    }

    private BatchDataset getSomeDataset(int numberOfEntries) throws Exception {
        // create a temporary batch to extract a fully constructed dataset
        createTestJson(BatchState.Stage.CREATE_DATASET, false, numberOfEntries);
        BatchDataset dataset = BatchState.createOrResume(true).getDataset();
        Files.delete(getJsonFile().toPath());
        return dataset;
    }

    private void createTestJson(BatchState.Stage stage, boolean ppcArchitecture, int fileCount, int... processedSoFarIndices) {
        createJson(getJsonFile(), stage, ppcArchitecture, fileCount, processedSoFarIndices);
    }

    private void createTestBackupJson(BatchState.Stage stage, boolean ppcArchitecture, int fileCount, int... processedSoFarIndices) {
        createJson(getJsonBackupFile(), stage, ppcArchitecture, fileCount, processedSoFarIndices);
    }

    private void createJson(File jsonFile, BatchState.Stage stage, boolean ppcArchitecture, int fileCount, int... processedSoFarIndices) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"lastCompletedStage\" : \"").append(stage).append("\",\n");
        if (fileCount < 0) {
            sb.append("  \"dataset\" : null\n  \"isFileProcessed\" : null\n  \"similarityMatrix\" : null");
        } else {
            boolean[] isProcessed = new boolean[fileCount];
            double[][] matrix = new double[fileCount][fileCount];
            for (int i : processedSoFarIndices) {
                isProcessed[i] = true;
                for (int j = 0; j < fileCount; ++j) {
                    matrix[i][j] = similarities[(i + j) % similarities.length];
                    matrix[i][i] = 1.0;
                }
            }
            String[] entries = new String[fileCount];
            for (int i = 0; i < fileCount; ++i) {
                entries[i] = "{\n      \"matrixIndex\" : " + i + ",\n      " + entriesParts[i % entriesParts.length] + "\n    }";
            }

            sb.append("  \"dataset\" : {\n");
            sb.append("    \"arch\" : {\n      ").append(ppcArchitecture ? architectures[1] : architectures[0]).append("\n    },\n");
            sb.append("    \"mergeFunctions\" : false,\n");
            sb.append("    \"entries\" : ").append(Arrays.toString(entries)).append("\n");
            sb.append("  },\n");
            sb.append("  \"isFileProcessed\" : ").append(Arrays.toString(isProcessed)).append(",\n");
            sb.append("  \"similarityMatrix\" : ").append(Arrays.deepToString(matrix)).append("\n");
        }
        sb.append("}\n");

        try {
            if (!jsonFile.createNewFile()) {
                throw new RuntimeException("Problem with test implementation: file with the name '" + jsonFile + "' already exists in the test folder");
            }
            FileWriter writer = new FileWriter(jsonFile);
            writer.write(sb.toString());
            writer.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void createOrResume_givenNotResumable_shouldCreateANotResumableBatch_whenNoFileExist() throws Exception {
        BatchState batch = BatchState.createOrResume(false);

        assertEquals(BatchState.Stage.CREATE_INSTANCE, batch.getLastCompletedStage());
        assertNull(batch.getDataset());
        assertNull(batch.getSimilarityMatrix());
        assertFalse(getJsonFile().exists());
    }

    @Test
    public void createOrResume_givenNotResumable_shouldCreateANotResumableBatch_evenWhenFileExist() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 3, 2);
        BatchState batch = BatchState.createOrResume(false);

        assertEquals(BatchState.Stage.CREATE_INSTANCE, batch.getLastCompletedStage());
        assertNull(batch.getDataset());
        assertNull(batch.getSimilarityMatrix());
    }

    @Test
    public void createOrResume_givenResumable_shouldCreateNewResumableBatch_whenNoFileExist() throws Exception {
        BatchState batch = BatchState.createOrResume(true);

        assertEquals(BatchState.Stage.CREATE_INSTANCE, batch.getLastCompletedStage());
        assertNull(batch.getDataset());
        assertNull(batch.getSimilarityMatrix());
        assertTrue(getJsonFile().isFile());
        assertFalse(getJsonBackupFile().exists());
    }

    @Test
    public void createOrResume_givenResumable_shouldReuseFile_whenFileExist() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 3, 1);
        BatchState batch = BatchState.createOrResume(true);

        assertEquals(BatchState.Stage.INDEX_FILES, batch.getLastCompletedStage());
        assertEquals(Architecture.ArchitectureType.ppc, batch.getDataset().getArchitecture().getType());
        assertNotNull(batch.getDataset());
        assertEquals(3, batch.getDataset().size());
        assertEquals(List.of(1), batch.getAlreadyDoneFiles());
    }

    @Test
    public void createOrResume_givenResumable_shouldRecoverFromBackupFileAndReplaceNormal_whenNormalFileDoesNotExist() throws Exception {
        createTestBackupJson(BatchState.Stage.CREATE_DATASET, false, 7, 5);

        BatchState batch = BatchState.createOrResume(true);

        assertFalse(getJsonBackupFile().exists());
        assertTrue(getJsonFile().isFile());
        assertEquals(BatchState.Stage.CREATE_DATASET, batch.getLastCompletedStage());
        assertEquals(Architecture.ArchitectureType.metapc, batch.getDataset().getArchitecture().getType());
        assertNotNull(batch.getDataset());
        assertEquals(7, batch.getDataset().size());
        assertEquals(List.of(5), batch.getAlreadyDoneFiles());
    }

    @Test
    public void createOrResume_givenResumable_shouldRecoverFromBackupFileAndReplaceNormal_whenNormalFileIsInvalid() throws Exception {
        createTestBackupJson(BatchState.Stage.INDEX_FILES, true, 4, 1);

        // simulate an interruption while writing the json file
        createTestJson(BatchState.Stage.INDEX_FILES, false, 3, 0);
        RandomAccessFile normalFile = new RandomAccessFile(getJsonFile(), "rw");
        normalFile.setLength(666);
        normalFile.close();

        BatchState batch = BatchState.createOrResume(true);

        assertFalse(getJsonBackupFile().exists());
        assertTrue(getJsonFile().isFile());
        assertEquals(BatchState.Stage.INDEX_FILES, batch.getLastCompletedStage());
        assertEquals(Architecture.ArchitectureType.ppc, batch.getDataset().getArchitecture().getType());
        assertNotNull(batch.getDataset());
        assertEquals(4, batch.getDataset().size());
        assertEquals(List.of(1), batch.getAlreadyDoneFiles());
    }


    @Test
    public void createOrResume_givenResumable_shouldIgnoreAndRemoveBackupFile_whenBothNormalAndBackupFileExist() throws Exception {
        createTestBackupJson(BatchState.Stage.INDEX_FILES, true, 6, 4);
        createTestJson(BatchState.Stage.INDEX_FILES, false, 4, 2);

        BatchState batch = BatchState.createOrResume(true);

        assertFalse(getJsonBackupFile().exists());
        assertTrue(getJsonFile().isFile());
        assertEquals(BatchState.Stage.INDEX_FILES, batch.getLastCompletedStage());
        assertEquals(Architecture.ArchitectureType.metapc, batch.getDataset().getArchitecture().getType());
        assertNotNull(batch.getDataset());
        assertEquals(4, batch.getDataset().size());
        assertEquals(List.of(2), batch.getAlreadyDoneFiles());
    }

    @Test(expected = IOException.class)
    public void createOrResume_givenResumable_shouldThrow_whenDataIsUnrecognized() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 6, 0);
        RandomAccessFile normalFile = new RandomAccessFile(getJsonFile(), "rw");
        normalFile.seek(32);
        normalFile.write("ZEBRA".getBytes());
        normalFile.close();

        BatchState.createOrResume(true);
    }

    @Test
    public void notifyDatasetCreated_givenDataset_shouldAdvanceStageAndCreateArraysAndWriteFile_whenInProperStage() throws Exception {
        BatchDataset dataset = getSomeDataset(14);
        BatchState batch = BatchState.createOrResume(true);

        batch.notifyDatasetCreated(dataset);
        // read back the just committed batch state (supposed to be) in other variable
        BatchState otherBatch = BatchState.createOrResume(true);

        assertEquals(BatchState.Stage.CREATE_DATASET, batch.getLastCompletedStage());
        assertEquals(dataset, batch.getDataset());
        assertEquals(14, batch.getDataset().size());
        assertEquals(14, batch.getFilesToProcess().size());
        assertEquals(0, batch.getAlreadyDoneFiles().size());
        assertEquals(14, batch.getSimilarityMatrix().length);
        assertEquals(14, batch.getSimilarityMatrix()[0].length);

        assertEquals(BatchState.Stage.CREATE_DATASET, otherBatch.getLastCompletedStage());
        assertEquals(14, otherBatch.getDataset().size());
        assertEquals(14, otherBatch.getFilesToProcess().size());
        assertEquals(0, otherBatch.getAlreadyDoneFiles().size());
        assertEquals(14, otherBatch.getSimilarityMatrix().length);
        assertEquals(14, otherBatch.getSimilarityMatrix()[0].length);
    }

    @Test(expected = RuntimeException.class)
    public void notifyDatasetCreated_givenDataset_shouldThrow_whenNotInProperStage() throws Exception {
        BatchDataset dataset = getSomeDataset(13);
        createTestJson(BatchState.Stage.CREATE_DATASET, true, 6);
        BatchState batch = BatchState.createOrResume(true);

        batch.notifyDatasetCreated(dataset);
    }

    @Test
    public void notifyIndexingDone_shouldAdvanceStageAndWriteFile_whenInProperStage() throws Exception {
        createTestJson(BatchState.Stage.CREATE_DATASET, false, 8);
        BatchState batch = BatchState.createOrResume(true);

        batch.notifyIndexingDone();
        // read back the normally just committed batch state in other variable
        BatchState otherBatch = BatchState.createOrResume(true);

        assertEquals(BatchState.Stage.INDEX_FILES, batch.getLastCompletedStage());
        assertEquals(BatchState.Stage.INDEX_FILES, otherBatch.getLastCompletedStage());
    }

    @Test(expected = RuntimeException.class)
    public void notifyIndexingDone_shouldThrow_whenNotInProperStage() throws Exception {
        BatchState batch = BatchState.createOrResume(false);

        batch.notifyIndexingDone();
    }


    @Test
    public void getAlreadyDoneFiles_shouldReturnEmptyList_whenNotIndexedYet() throws Exception {
        BatchState batch = BatchState.createOrResume(false);

        List<Integer> done = batch.getAlreadyDoneFiles();

        assertEquals(0, done.size());
    }

    @Test
    public void getAlreadyDoneFiles_shouldReturnEmptyList_whenNoFileDoneYet() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 3);
        BatchState batch = BatchState.createOrResume(true);

        List<Integer> done = batch.getAlreadyDoneFiles();

        assertEquals(0, done.size());
    }

    @Test
    public void getAlreadyDoneFiles_shouldReturnActualFileDone_whenSomeFilesAreProcessed() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 4, 1, 3);
        BatchState batch = BatchState.createOrResume(true);

        List<Integer> done = batch.getAlreadyDoneFiles();

        assertArrayEquals(new Integer[]{1, 3}, done.toArray());
    }

    @Test
    public void getFilesToProcess_shouldReturnEmptyList_whenNotIndexedYet() throws Exception {
        BatchState batch = BatchState.createOrResume(false);

        List<Integer> done = batch.getFilesToProcess();

        assertEquals(0, done.size());
    }

    @Test
    public void getFilesToProcess_shouldReturnAllIndices_whenNoFileDoneYet() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 5);
        BatchState batch = BatchState.createOrResume(true);

        List<Integer> done = batch.getFilesToProcess();

        assertArrayEquals(new Integer[]{0, 1, 2, 3, 4}, done.toArray());
    }

    @Test
    public void getFilesToProcess_shouldReturnRemainingFilesToDo_whenSomeFilesAreProcessed() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 4, 1, 3);
        BatchState batch = BatchState.createOrResume(true);

        List<Integer> done = batch.getFilesToProcess();

        assertArrayEquals(new Integer[]{0, 2}, done.toArray());
    }

    @Test
    public void notifyFileProcessed_givenSomeIndex_shouldUpdateFilesDoneAndTodo() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, true, 6, 0, 1);
        BatchState batch = BatchState.createOrResume(true);

        double[] dummySimilarity = {0.1, 0.2, 0.3, 1.0, 0.5, 0.6};
        batch.notifyFileProcessed(3, dummySimilarity);
        // read back the normally just committed batch state in other variable
        BatchState otherBatch = BatchState.createOrResume(true);

        assertArrayEquals(new Integer[]{0, 1, 3}, batch.getAlreadyDoneFiles().toArray());
        assertArrayEquals(new Integer[]{0, 1, 3}, otherBatch.getAlreadyDoneFiles().toArray());
        assertArrayEquals(new Integer[]{2, 4, 5}, batch.getFilesToProcess().toArray());
        assertArrayEquals(new Integer[]{2, 4, 5}, otherBatch.getFilesToProcess().toArray());
    }

    @Test
    public void getSimilarityMatrix_givenFileResults_shouldReturnGivenResultsSoFarOtherwiseZero() throws Exception {
        createTestJson(BatchState.Stage.INDEX_FILES, false, 4);
        BatchState batch = BatchState.createOrResume(true);
        batch.notifyFileProcessed(0, new double[]{1.000, 0.125, 0.250, 0.375});
        batch.notifyFileProcessed(1, new double[]{0.500, 1.000, 0.625, 0.750});
        batch.notifyFileProcessed(3, new double[]{0.875, 0.000, 0.125, 1.000});

        double[][] matrix = batch.getSimilarityMatrix();

        assertEquals(4, matrix.length);
        assertArrayEquals(new double[]{1.000, 0.125, 0.250, 0.375}, matrix[0], 0.0);
        assertArrayEquals(new double[]{0.500, 1.000, 0.625, 0.750}, matrix[1], 0.0);
        assertArrayEquals(new double[]{0.000, 0.000, 0.000, 0.000}, matrix[2], 0.0);
        assertArrayEquals(new double[]{0.875, 0.000, 0.125, 1.000}, matrix[3], 0.0);
    }

    @Test
    public void notifyCompleted_givenResumableBatch_shouldDeleteFile_whenFromAnyValidStage() throws Exception {
        for (BatchState.Stage stage : BatchState.Stage.values()) {
            createTestJson(stage, false, stage.compareTo(BatchState.Stage.CREATE_DATASET) >= 0 ? 4 : 0);
            BatchState batch = BatchState.createOrResume(true);

            batch.notifyCompleted();

            assertFalse(getJsonFile().exists());
            assertFalse(getJsonBackupFile().exists());
        }
    }
}