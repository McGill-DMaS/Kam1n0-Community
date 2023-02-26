package ca.mcgill.sis.dmas.kam1n0.cli;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.kam1n0.cli.dgen.Exp;

import java.io.FileOutputStream;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;

public class ConvertSimilarity {
    private static final Logger logger = LoggerFactory.getLogger(ConvertSimilarity.class);

    public static void process(File inputFile, File outputFile) {
        logger.info(String.format("Convert file: %s to excel %s.", inputFile.getName(), outputFile.getName()));
        var heatMapData = new Batch2.HeatMapData();

        if (inputFile.exists() && !inputFile.isDirectory()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                var result = mapper.readerFor(Batch2.Result.class).readValue(inputFile);

                var contents= ((Batch2.Result)result).contents;
                heatMapData= contents.get(getFirstElementName(contents));
            }
            catch (Exception ex) {
                logger.error(String.format("Error reading file: %s", ex.toString()));
            }

            var data = convertMapDataToExcelData(heatMapData);
            var workbook = fillSheetFrom(data);
            try
            {
                FileOutputStream out = new FileOutputStream(outputFile);
                workbook.write(out);
                out.close();
                logger.info(String.format("%s file was successfully written to disk.", outputFile.getAbsolutePath()));
            }
            catch (Exception ex)
            {
                logger.error(String.format("Error writing file: %s", ex.toString()));
            }
        }
    }

    private static String getFirstElementName(Map<String, Batch2.HeatMapData> contents) {
        return (String)contents.keySet().toArray()[0];
    }

    private static XSSFWorkbook fillSheetFrom(Map<Integer, Object[]> data) {
        var workbook = new XSSFWorkbook();
        var sheet = workbook.createSheet("Similarity");
        var style = workbook.createCellStyle();
        var font = workbook.createFont();
        font.setBold(true);
        style.setFont(font);

        //Iterate over data and write to sheet
        var keySet = data.keySet();
        var rowNumber = 0;
        for (var key : keySet)
        {
            var excelRow = sheet.createRow(rowNumber++);

            var objArr = data.get(key);
            var cellNumber = 0;
            for (Object obj : objArr)
            {
                Cell cell = excelRow.createCell(cellNumber++);
                if (obj instanceof String)
                    cell.setCellValue((String)obj);
                else if(obj instanceof Integer)
                    cell.setCellValue((Integer)obj);
                else if(obj instanceof Float)
                    cell.setCellValue((Float)obj);
                else if(obj instanceof Double)
                    cell.setCellValue((Double)obj);
                if (rowNumber == 1 || cellNumber == 1)
                    cell.setCellStyle(style);
            }
        }
        sheet.autoSizeColumn(0);
        return workbook;
    }

    @NotNull
    private static Map<Integer, Object[]> convertMapDataToExcelData(Batch2.HeatMapData heatMapData) {
        Map<Integer, Object[]> data = new TreeMap<>();
        var column = 0;
        var row = 1;
        var labelObject = new Object[heatMapData.labels.size() + 1];
        labelObject[column] = "";
        column++;
        for (var label: heatMapData.labels){
            labelObject[column] = label;
            column++;
        }
        data.put(row, labelObject);
        row++;
        for (var similarity: heatMapData.similarity){
            var similarityObject = new Object[similarity.length + 1];
            column = 0;
            similarityObject[column] = heatMapData.labels.get(row - 2);
            column++;

            for (var value: similarity){
                similarityObject[column] = value;
                column++;
            }
            data.put(row, similarityObject);
            row++;
        }
        return data;
    }

    public static class BatchFunction extends CLIFunction {
        private final ArgumentParser parser = ArgumentParser.create(Exp.class.getSimpleName());
        private final ArgumentParser.Option op_input = parser.addOption("input", ArgumentParser.OpType.File, false,
                "The [path] and the name of the input file", new File("similarity.txt"));
        private final ArgumentParser.Option op_output = parser.addOption("output", ArgumentParser.OpType.File, false,
                "The [path] and the name of the output result file.", new File("similarity.xlsx"));

        @Override
        public ArgumentParser getParser() {
            return this.parser;
        }

        @Override
        public String getDescription() {
            return "Convert similarity.txt to Excel";
        }

        @Override
        public String getCode() {
            return "c";
        }
        @Override
        public void process(String[] args) {
            if (!parser.parse(args)) {
                System.exit(0);
            }

            try {
                ConvertSimilarity.process(op_input.getValue(), op_output.getValue());

            } catch (Exception e) {
                logger.info("Failed to process " + Arrays.toString(args), e);
            }
            System.exit(0);
        }
        @Override
        public String getCategory() {
            return "JAR Utilities";
        }
    }
}