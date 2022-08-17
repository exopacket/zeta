package com.inteliense.trusty.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;

public class Exec {

    public static void noOut(String cmd) throws IOException {

            ProcessBuilder builder = new ProcessBuilder();
            builder.command("/bin/sh", "-c", cmd);
            builder.start();

    }

    public static void runAndWait(String cmd) throws IOException, InterruptedException {

        ProcessBuilder builder = new ProcessBuilder();
        builder.command("/bin/sh", "-c", cmd);
        Process process = builder.start();

        process.waitFor();

    }

    public static String[] withOut(String cmd) throws IOException, InterruptedException {

        ProcessBuilder builder = new ProcessBuilder();
        builder.command("/bin/sh", "-c", cmd);
        Process process = builder.start();

        StringBuilder output = new StringBuilder();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));

        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line + "\n");
        }

        int exitVal = process.waitFor();
        if (exitVal == 0) {
            return output.toString().split("\\n");
        }

        return new String[]{""};

    }

    public static int background(String cmd) throws IOException, InterruptedException {

        ProcessBuilder builder = new ProcessBuilder();
        builder.command("/bin/sh", "-c", cmd, "&");
        Process process = builder.start();

        StringBuilder output = new StringBuilder();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));

        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line + "\n");
        }

        int exitVal = process.waitFor();
        if (exitVal == 0) {
            int processId = -1;
            try {
                processId = Integer.parseInt(output.toString().split("\\n")[0]);
            } catch(Exception ex) {

            }
            return processId;
        }

        return 0;

    }

    public static String getJarPath() throws URISyntaxException {

        String path = new File(Exec.class.getProtectionDomain().getCodeSource().getLocation()
                .toURI()).getPath();

        path = path.replaceAll("(\\/[a-zA-Z0-9]+\\.jar)", "");

        return path;

    }

    public static int getUID() {

        try {

            String userName = System.getProperty("user.name");

            String[] out = withOut("id -u " + userName);

            return Integer.parseInt(out[0]);

        } catch (Exception ex) {
            ex.printStackTrace();
            return -1;
        }

    }

}
