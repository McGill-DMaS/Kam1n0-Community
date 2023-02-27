package ca.mcgill.sis.dmas.kam1n0.cli;

import ca.mcgill.sis.dmas.env.DmasApplication;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ConvertSimilarityTest {

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

    private static final String resultTextFilename = "similarity.txt";
    private static final String resultExcelFilename = "similarity.xlsx";

    private File getResultFile() {
        return new File(tmpFolder.getRoot(), resultTextFilename);
    }

    private File getExcelFile() {
        return new File(tmpFolder.getRoot(), resultExcelFilename);
    }

    private double[][] getResultData() {
        var data = new double[4][4];
        data[0][0] = 0; data[0][1] = 1; data[0][2] = 2; data[0][3] = 3;
        data[1][0] = 100; data[1][1] = 101; data[1][2] = 102; data[1][3] = 103;
        data[2][0] = 200; data[2][1] = 201; data[2][2] = 202; data[2][3] = 203;
        data[3][0] = 300; data[3][1] = 301; data[3][2] = 302; data[3][3] = 303;
        return data;
    }
    private ArrayList<String> getResultLabel() {
        var labels = new ArrayList<String>();
        labels.add("label_1");
        labels.add("label_2");
        labels.add("label_3");
        labels.add("label_4");
        return labels;
    }

    private Batch2.Result createResultFile(String modelKey) {
        var mapper = new ObjectMapper();
        var result = new Batch2.Result();

        result.put(modelKey, getResultData(), getResultLabel());
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(getResultFile(), result);
        } catch (IOException e) {}
        return result;
    }

    @Test
    public void givenResultTextFile_whenHavingData_thenDataAreInExcelFile() {
        var modelKey = "modelKey";
        createResultFile(modelKey);

        var convertSimilarity = new ConvertSimilarity();
        convertSimilarity.process(getResultFile(), getExcelFile());

        try {
            var file = new FileInputStream(getExcelFile());
            var workbook = new XSSFWorkbook(file);
            var sheet = workbook.getSheetAt(0);
            Iterator<Row> rowIterator = sheet.iterator();
            var rowCount = 0;
            var columnCount = 0;
            var labels = getResultLabel();
            var data = getResultData();
            while (rowIterator.hasNext())
            {
                Row row = rowIterator.next();
                Iterator<Cell> cellIterator = row.cellIterator();

                while (cellIterator.hasNext())
                {
                    Cell cell = cellIterator.next();
                    if (cell.getCellType() == CellType.NUMERIC) {
                        if (rowCount != 0 && columnCount != 0) {
                            assertEquals(data[rowCount-1][columnCount-1], cell.getNumericCellValue(), 0.0001);
                        }
                    }
                    else if (cell.getCellType() == CellType.STRING) {
                        if (columnCount == 0 && rowCount == 0)
                            assertEquals("", cell.getStringCellValue());
                        else if (rowCount == 0 || columnCount == 0) {
                            int labelIndex = rowCount == 0 ? columnCount - 1 : (columnCount == 0 ? rowCount - 1 : rowCount);
                            assertEquals(labels.get(labelIndex), cell.getStringCellValue());
                        }
                    }
                    columnCount++;
                }
                columnCount = 0;
                rowCount++;
                System.out.println("");
            }
            file.close();
        }
        catch (Exception e)
        {
            System.out.println("The test is in error an exception has been thrown." + e);
            assertFalse(true);
        }
    }

    @Test
    public void Result_givenResult_whenKeyProvided_thenLabelAndDataAreInResult() {
        var modelKey = "modelKey";
        var result = createResultFile(modelKey);
        var expected_data = result.contents.get(modelKey);

        assertEquals(expected_data.similarity, getResultData());
        assertEquals(expected_data.labels, getResultLabel());
    }
}