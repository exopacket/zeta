package com.inteliense.trusty.utils;


import java.io.IOException;

public class Pushover {

    private static String apiKey = "adqr1rcn5cdxyj5ov4743kkrq5t46x";
    private static String clientKey = "ucy2523v1njakzrpfib37iq5d87fi6";

    public static void newNotification(String title, String message) {

        try {

            new Notification(title, message);

        } catch (Exception ex) {

            System.out.println("Couldn't send Pushover notification.");

        }

    }

    private static class Notification {

        public Notification(String title, String message) throws IOException {

            final String URL = "https://api.pushover.net/1/messages.json";
            final String MESSAGE = title + "\n\n" + message;
            final String DATA = "token=" + apiKey + "&user=" + clientKey + "&message=" + MESSAGE;

            exec(new String[] {"curl", "-X", "POST", URL, "--data", DATA});

        }

        private void exec(String[] args) throws IOException {

            Process proc = new ProcessBuilder(args).start();

        }

    }

}
