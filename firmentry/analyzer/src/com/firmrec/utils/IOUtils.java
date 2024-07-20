package com.firmrec.utils;

import org.bouncycastle.util.encoders.Hex;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;

public class IOUtils {
    public static Object loadYAML(String yamlPath) {
        Object result = null;
        Yaml yaml = new Yaml();
        try {
            InputStream inputStream = new FileInputStream(yamlPath);
            result = yaml.load(inputStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String getFileMD5(String filePath) {
        File file = new File(filePath);
        FileInputStream fileInputStream = null;
        try {
            MessageDigest MD5 = MessageDigest.getInstance("MD5");
            fileInputStream = new FileInputStream(file);
            byte[] buffer = new byte[8192];
            int length;
            while ((length = fileInputStream.read(buffer)) != -1) {
                MD5.update(buffer, 0, length);
            }
            return new String(Hex.encode(MD5.digest()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static Object loadCache(String projectDirectory, String name) {
        Path cachePath = Path.of(projectDirectory, ".cache");
        File cacheDirectory = cachePath.toFile();
        if (!cacheDirectory.exists() || !cacheDirectory.isDirectory()) {
            return null;
        }
        HashMap<String, Object> results = null;
        Path cacheTotalPath = Path.of(cachePath.toString(), name);
        try {
            FileInputStream fileIn = new FileInputStream(cacheTotalPath.toString());
            ObjectInputStream objectIn = new ObjectInputStream(fileIn);
            results = (HashMap<String, Object>) objectIn.readObject();
            objectIn.close();
            fileIn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return results;
    }

    public static void storeCache(String projectDirectory, String name, Object items) {
        Path cachePath = Path.of(projectDirectory, ".cache");
        File cacheDirectory = cachePath.toFile();
        if (!cacheDirectory.exists()) {
            cacheDirectory.mkdir();
        }
        Path cacheTotalPath = Path.of(cachePath.toString(), name);
        try {
            FileOutputStream fileOut = new FileOutputStream(cacheTotalPath.toString());
            ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
            objectOut.writeObject(items);
            objectOut.close();
            fileOut.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
