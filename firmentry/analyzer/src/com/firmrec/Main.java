package com.firmrec;

import com.google.gson.JsonArray;
import com.firmrec.analyzer.GhidraWrapper;
import com.firmrec.analyzer.ProgramAnalyzer;
import com.firmrec.analyzer.plugin.IoTPlugin;
import com.firmrec.model.ProgramFunction;
import com.firmrec.storage.InputStorage;
import com.firmrec.utils.IOUtils;
import ghidra.program.model.pcode.HighFunction;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {

    private static void doExtractInputLocation(String configPath, String binaryPath, String stringPath,
            String dbName) {

        File file = new File(stringPath);
        String stringContent = null;
        try {
            stringContent = FileUtils.readFileToString(file, "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (stringContent == null)
            return;

        JSONArray strings;
        try {
            strings = new JSONArray(stringContent);
        } catch (Exception e) {
            JSONObject jsonObject = new JSONObject(stringContent);
            strings = new JSONArray();
            for (String field : JSONObject.getNames(jsonObject)) {
                strings.putAll(jsonObject.getJSONArray(field));
            }
        }
        ArrayList<String> stringArray = new ArrayList<>();
        for (int i = 0; i < strings.length(); ++i) {
            stringArray.add((String) strings.get(i));
        }

        Map<String, String> basicConfig = (Map<String, String>) IOUtils.loadYAML(configPath);
        GhidraWrapper ghidraWrapper = new GhidraWrapper(basicConfig.get("project_path"));
        ProgramAnalyzer analyzer = ghidraWrapper.loadBinary(binaryPath, null, null);
        analyzer.addPlugin(new IoTPlugin());
        IoTPlugin plugin = (IoTPlugin) analyzer.getPlugin(0);

        // plugin.extractInputLocation(analyzer, stringArray, outputPath);
        try {
            String user = basicConfig.get("db_user");
            String passwd = basicConfig.get("db_user_passwd");
            InputStorage storage = new InputStorage(user, passwd, dbName);
            plugin.extractToDatabase(analyzer, stringArray, storage);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        analyzer.close();
        ghidraWrapper.unloadBinary();

        System.out.println("Done!");
    }

    public static void main(String[] args) {
        String configPath = args[0];
        String binaryPath = args[1];
        String stringPath = args[2];
        String dbName = args[3];

        doExtractInputLocation(configPath, binaryPath, stringPath, dbName);
    }
}
