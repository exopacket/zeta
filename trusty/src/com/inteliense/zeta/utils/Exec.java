package com.inteliense.trusty.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;

public class Exec {

    public static void noOut(String cmd) throws IOException {

            String[] terminalRes = getTerminal();

            ProcessBuilder builder = new ProcessBuilder();
            builder.command(terminalRes[0], terminalRes[1], cmd);
            builder.start();

    }

    public static void runAndWait(String cmd) throws IOException, InterruptedException {

        String[] terminalRes = getTerminal();

        ProcessBuilder builder = new ProcessBuilder();
        builder.command(terminalRes[0], terminalRes[1], cmd);
        Process process = builder.start();

        process.waitFor();

    }

    public static String[] withOut(String cmd) throws IOException, InterruptedException {

        String[] terminalRes = getTerminal();

        ProcessBuilder builder = new ProcessBuilder();
        builder.command(terminalRes[0], terminalRes[1], cmd);
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

    public static String checkOsPath(String path) {
        if(getOs() == OpSys.OS.WINDOWS) {
            return path.replace("/", "\\");
        } else {
            return path.replace("\\", "/");
        }
    }

    public static int background(String cmd) throws IOException, InterruptedException {

        ProcessBuilder builder = new ProcessBuilder();

        if(getOs() == OpSys.OS.WINDOWS) {
            builder.command("cmd.exe", "start", "/b", cmd);
        } else {
            builder.command("/bin/sh", "-c", cmd, "&");
        }

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

    public static OpSys.OS getOs() {
        return OpSys.getOS();
    }

    public static String getJarPath() {

        try {

            String path = new File(Exec.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI()).getPath();

            path = path.replaceAll("((\\/||\\\\)[a-zA-Z0-9]+\\.jar)", "");

            path = ((getOs() == OpSys.OS.WINDOWS) ? "\\" : "/") + path;

            return path;

        } catch(Exception ex) {
            ex.printStackTrace();
            return "";
        }

    }

    public static int getUnixUID() {

        try {

            String userName = System.getProperty("user.name");

            String[] out = withOut("id -u " + userName);

            return Integer.parseInt(out[0]);

        } catch (Exception ex) {
            ex.printStackTrace();
            return -1;
        }

    }

    private static String[] getTerminal() {
        OpSys.OS os = OpSys.getOS();
        switch(os) {
            case WINDOWS:
                return new String[]{"cmd.exe", "/c"};
            default:
                return new String[]{"/bin/sh", "-c"};
        }
    }

    public static class OpSys {
        public enum OS {
            WINDOWS, LINUX, MAC, SOLARIS
        };// Operating systems.

        private static OS os = null;

        public static OS getOS() {
            if (os == null) {
                String operSys = System.getProperty("os.name").toLowerCase();
                if (operSys.contains("win")) {
                    os = OS.WINDOWS;
                } else if (operSys.contains("nix") || operSys.contains("nux")
                        || operSys.contains("aix")) {
                    os = OS.LINUX;
                } else if (operSys.contains("mac")) {
                    os = OS.MAC;
                } else if (operSys.contains("sunos")) {
                    os = OS.SOLARIS;
                }
            }
            return os;
        }
    }

}
