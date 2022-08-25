package com.inteliense.trusty.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

public abstract class SocketServer implements SocketRequest {

    private ArrayList<Socket> socket = new ArrayList<Socket>();
    private ServerSocket serverSocket;
    private ArrayList<BufferedReader> in = new ArrayList<BufferedReader>();
    private ArrayList<PrintWriter> out = new ArrayList<PrintWriter>();
    private int port;

    private InetAddress bindAddr;

    public SocketServer(String addr, int port) throws Exception {

        bindAddr = InetAddress.getByName(addr);
        this.port = port;
        start();

    }

    private void start() throws InterruptedException {

        Thread thread = new Thread(() -> {

            try {
                create();
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            while(true) {

                boolean accepted = false;
                int _index = -1;

                try {

                    int index = accept();
                    accepted = true;
                    _index = index;

                    Thread actionThread = new Thread(() -> {

                        try {
                            parse(read(index), index);
                            end(index);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                    });

                    actionThread.start();

                } catch (Exception ex) {

                    if(accepted) {
                        try {
                            end(_index);
                            stop(_index);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                    ex.printStackTrace();
                    break;

                }

            }

        });

        thread.start();
        thread.join();

    }

    public void stop(int index) throws IOException {

        serverSocket.close();
        socket.get(index).close();

    }

    private void create() throws IOException {

        serverSocket = new ServerSocket(port, 111, bindAddr);

    }

    private int accept() throws IOException {

        Socket socket = serverSocket.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), false);

        this.socket.add(socket);
        this.in.add(in);
        this.out.add(out);

        return this.socket.size() - 1;

    }

    private void end(int index) throws IOException {

        in.get(index).close();
        out.get(index).close();
        socket.get(index).close();

    }

    private String[] read(int index) throws IOException {

        Scanner scnr = new Scanner(in.get(index));

        String input = scnr.nextLine() + "\n";

        while(scnr.hasNextLine()) {

            String _input = scnr.nextLine();

            if(_input.length() == 1) {

                char c = _input.charAt(0);
                if(c=='\31') {
                    //System.out.println("-EOF-");
                    break;
                }

            }

            input += _input;
            //System.out.println(input);
            input += '\n';

        }

        //System.out.println(input);

        return input.split("\\n");

    }

    public void write(String output, int index) {

        //System.out.println(output);
        out.get(index).print(output);
        out.get(index).close();
        out.get(index).flush();

    }

    private void parse(String[] lines, int index) throws Exception {

        //System.out.println("new request!");
        newRequest(lines, index);

    }

}
