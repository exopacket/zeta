package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.JSON;
import com.sun.net.httpserver.*;
import org.json.simple.JSONObject;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

//REST

//  - Return data immediately

//REST ASYNC
//  - Return immediately redirect url, initial period, and response ID

//ZeroTrust ASYNC
//  - Request consists of
//      - Request Timestamp (client's time)
//      - Request Server Public Key ID (different for each client / same public key)
//      - Request Client Public Key ID
//      - [Encrypted by server public key]
//          - Key ID (optional)
//          - Request hash512(HMAC 256(full_request, api_key)))
//          - Body hash512(HMAC 256(request_body, api_key)));
//          - [Encrypted with AES-GCM-256] (optional)
//              - API Key
//              - Authentication [Request] Cookie (Most recent dynamic cookie)
//              - Client ID [Client Session] Cookie
//              - Request Body

//  - Get Client Session init consists of
//      - User ID
//      - Registered Client ID
//      - hash256(HMAC 256(ip_address, api_key)));
//  - Returns Client Session Cookie (fake response if not accepted)
//      - Initial Authentication Cookie is created by HMAC 256(client_session_cookie, api_key)

//  - Get PUBKEY request consists of
//      - User ID
//      - Client Session ID
//      - Client Public Key ID
//      - hash512(HMAC 256(client_session_id, registered_client_id));
//  - Returns public key ID, public key, random bytes for GCM

//  - Response consists of
//      - Server Timestamp
//      - Dynamic cookie (AKA Authentication [Request] Cookie)
//      - Response ID
//      - Initial Poll Rate

//  - Async Get Response consists of
//      - Client timestamp
//      - Request dynamic cookie value
//      - Response ID
//      - API Key
//      - Client Session ID

//  - Not ready response
//      - auth_success
//      - new poll rate

//      - Request Timestamp (client's time)
//      - [Encrypted by client public key]
//          - Key ID (optional)
//          - Request hash512(HMAC 256(full_request, api_key)))
//          - Body hash512(HMAC 256(request_body, api_key)));
//          - [Encrypted with AES-GCM-256] (optional)
//              - Request Body

//ZeroTrust WebSocket same as above / just no polling

public abstract class APIServer implements APIRequestProcess, ClientFilter {

    private APIServerConfig config;
    private APIResponseServer responseServer;
    private APIResources resources = new APIResources();
    private ArrayList<RemoteClient> clients = new ArrayList<RemoteClient>();
    public APIServer(APIServerConfig config) throws APIException {

        this.config = config;

        if(config.getApiServerKeyPassword().equals("")) {
            throw new APIException("Server could not be started successfully. " +
                    "The keystore password is not set.");
        }

        if(config.getApiServerKeystorePath().equals("")) {
            throw new APIException("Server could not be started successfully. " +
                    "The keystore path is not set.");
        }

        if(config.getApiPath().equals("")) {
            throw new APIException("Server could not be started successfully. " +
                    "The API path is not set.");
        }

        if(config.getServerType() == APIServerType.ZeroTrust_HTTP || config.getServerType() == APIServerType.ZeroTrust_WEBSOCKET) {
            if(config.getSessionInitPath().equals("")) {
                throw new APIException("Server could not be started successfully. " +
                        "The API path is not set.");
            }
            if(config.getSessionKeyTransferPath().equals("")) {
                throw new APIException("Server could not be started successfully. " +
                        "The API path is not set.");
            }
            if(config.getSessionClosePath().equals("")) {
                throw new APIException("Server could not be started successfully. " +
                        "The API path is not set.");
            }
        }

        File tmpFile = new File(config.getApiServerKeystorePath());

        if(!tmpFile.exists()) {
            throw new APIException("Server could not be started successfully. " +
                    "The keystore doesn't exist at " + config.getApiServerKeystorePath());
        }

        tmpFile = new File(config.getResponseServerKeystorePath());

        if(!tmpFile.exists()) {
            throw new APIException("Server could not be started successfully. " +
                    "The keystore doesn't exist at " + config.getResponseServerKeystorePath());
        }


        tmpFile = null;

        switch(config.getServerType()) {
            case ZeroTrust_HTTP:
            case REST_ASYNC:
                startHttpsServer();
                startResponseServer();
                break;
            case REST_SYNC:
                startHttpsServer();
                break;
            case ZeroTrust_WEBSOCKET:
                startWebSocketServer();
                break;
        }

    }
    public void addResource(String value, APIResource definition) {
        resources.addResource(value, definition);
    }

    public void addResource(String value, String[] parameters, APIResource definition) {
        resources.addResource(value, parameters, definition);
    }

    public void addResource(String value, ArrayList<String> parameters, APIResource definition) {
        resources.addResource(value, parameters, definition);
    }

    public void addParameterToResource(String resource, String parameter) {
        resources.getResource(resource).addParameter(parameter);
    }

    public void setApiResources(APIResources apiResources) {
        resources = apiResources;
    }

    public APIResources getApiResources() {
        return resources;
    }

    public APIResponse execute(RemoteClient client, String resource, HashMap<String, String> parameters) {
        APIResource apiResource = getApiResources().getResource(resource);
        return apiResource.execute(client, parameters);
    }
    
    public APIResponse asyncExecute(RemoteClient client, String resource, HashMap<String, String> parameters) {

        try {

            APIResponse retVal = getRedirectResponse(client, resource, parameters);

            Thread t = new Thread(() -> {
                APIResource apiResource = getApiResources().getResource(resource);
                apiResource.execute(client, parameters);
                addAsyncRequest(client, resource, parameters, apiResource, retVal);
            });

            return retVal;

        } catch (APIException ex) {
            System.out.println(ex.getMessage());
        }

        return null;
        
    }

    public APIResponse getRedirectResponse(RemoteClient client, String resource, HashMap<String, String> parameters) throws APIException {

        return new APIResponse(client, config.getResponseServerPath(), (config.getServerType() == APIServerType.ZeroTrust_HTTP));

    }

    public void addAsyncRequest(RemoteClient client, String resourceType, HashMap<String, String> parameters, APIResource resource, APIResponse response) {
        responseServer.addRequest(client, resourceType, parameters, resource, response);
    }

    private void startHttpsServer() {

        HttpsServer server = null;

        try {

            server = HttpsServer.create(config.getBindAddress(), 0);

            SSLContext sslContext = SSLContext.getInstance("TLS");

            char[] keyPass = config.getApiServerKeyPassword().toCharArray();

            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fs = new FileInputStream(config.getApiServerKeystorePath());
            ks.load(fs, keyPass);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keyPass);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[32]; //20?
            random.nextBytes(bytes);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), random);

            server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {

                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                        params.setSSLParameters(defaultSSLParameters);

                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            });

            server.createContext(config.getApiPath(), new APIServerHandler());
            server.setExecutor(null); // creates a default executor
            server.start();

        } catch (IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException |
                 CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();

        }

    }

    private void startWebSocketServer() {

    }

    private void startResponseServer() {

    }

    public RemoteClient getRemoteClient(String ipAddress, String port, String hostname, String resource,
                                        String apiKey, String sessionId) throws APIException {

        for(int i=0; i<clients.size(); i++) {

            RemoteClient client = clients.get(i);
            if(client.getApiKey().equals(apiKey)) {

                if(config.getSessionInitPath().equals(resource)) {

                    if(client.getSessionId().equals(sessionId)
                            && client.getRemoteIp().equals(ipAddress))
                        return client;

                }

            }

        }

        return null;

    }

    public RemoteClient getRemoteClient(String ipAddress, String port, String hostname,
                                        String apiKey) throws APIException {

        for(int i=0; i<clients.size(); i++) {

            RemoteClient client = clients.get(i);
            if(client.getApiKey().equals(apiKey) && client.getRemoteIp().equals(ipAddress)) {

                return client;

            }

        }

        RemoteClient client = new RemoteClient(ipAddress, port, hostname, apiKey, this) {
            @Override
            public boolean isLimited(int perMinute) {
                return super.getServer().isPastRateLimit(this, perMinute);
            }

            @Override
            public boolean inBlacklist() {
                return super.getServer().inBlacklist(this);
            }

            @Override
            public boolean isAuthenticated() {
                return super.getServer().isAuthenticated(this);
            }

            @Override
            public boolean lookupApiKey(String apiKeyHeader) {
                return super.getServer().lookupApiKey(apiKeyHeader);
            }

            @Override
            public boolean lookupUserId(String apiKey, String clientId, String userId) {
                return super.getServer().lookupUserId(apiKey, clientId, userId);
            }

        };

        return client;

    }

    public APIServerConfig getConfig() {
        return config;
    }
    private static class RequestParser {

        public static boolean isEmpty(String body) {
            return (body.replaceAll("\\s+", "").equals(""));
        }

        public static boolean verifyJson(String body) {

            return !JSON.verify(body).equals("false");

        }

        public static JSONObject parseJson(String body, boolean wasVerified) {

            if(wasVerified) {

                String res = JSON.verify(body);

                if(res.equals("false")) {
                    return new JSONObject();
                } else {
                    return JSON.getObject(res);
                }

            } else {

                return new JSONObject();

            }

        }

        public static HashMap<String, String> queryToMap(String query) {
            if(query == null) {
                return null;
            }
            HashMap<String, String> result = new HashMap<>();
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                if (entry.length > 1) {
                    result.put(entry[0], entry[1]);
                }else{
                    result.put(entry[0], "");
                }
            }
            return result;
        }

        public static boolean verifyResource(APIResources resources, String resource) {

            return resources.inList(resource);

        }

    }

    private class APIServerHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange t) throws IOException {

            final Headers headers = t.getResponseHeaders();
            final String inboundRequestMethod = t.getRequestMethod().toUpperCase();

            String remoteAddr = t.getRemoteAddress().toString();
            String[] ipParts = remoteAddr.split(":");
            String leftSide = ipParts[0];
            String port = ipParts[1];
            String[] leftParts = leftSide.split("/");
            String hostname = leftParts[0];
            String ipAddr = leftParts[1];

            String resource = t.getRequestURI().getPath()
                    .replace(config.getApiPath() + "/","")
                    .replace(config.getApiPath(), "")
                    .replace("/", "_");

            if(!RequestParser.verifyResource(getApiResources(), resource)) {
                failRequest(t, "Invalid resource resource.");
            }
            
            String requestMethod = getApiResources().getResource(resource).getRequestMethod();
            if(config.getServerType() == APIServerType.ZeroTrust_HTTP)
                requestMethod = "POST";

            if(!inboundRequestMethod.equals(requestMethod)) {
                failRequest(t, "Invalid request method.");
                return;
            }

            if(!headers.containsKey("X-Api-Key")) {
                noApiKey(t);
                return;
            }

            String apiKey = headers.getFirst("X-Api-Key");
            String sessionId = null;
            RemoteClient client = null;
            if(config.getServerType() == APIServerType.ZeroTrust_HTTP) {
                if(!headers.containsKey("X-Api-Session-Id")) {
                    noApiKey(t);
                    return;
                }
                sessionId = headers.getFirst("X-Api-Session-Id");
                try {
                    client = getRemoteClient(ipAddr, port, hostname, resource, apiKey, sessionId);
                } catch (APIException ex) {
                    System.out.println(ex.getMessage());
                }
            } else {
                try {
                    client = getRemoteClient(ipAddr, port, hostname, apiKey);
                } catch (APIException ex) {
                    System.out.println(ex.getMessage());
                }
            }

            APIResponse response;
            boolean isAsync = false;

            if(config.getServerType() == APIServerType.REST_ASYNC)
                isAsync = true;
            
            if(requestMethod.equals("POST") && getApiResources().getResource(resource).requestIsJson()) {
                
                if(config.getServerType() == APIServerType.ZeroTrust_HTTP) {
                    response = processRequest(t, client, t.getRequestBody(), resource, ipAddr, port, hostname, true);
                } else {
                    response = processRequest(t, client, t.getRequestBody(), resource, null, null, null, isAsync);
                }
                
            } else if(requestMethod.equals("GET")) {
                
                response = processRequest(t, client, t.getRequestURI().getQuery(), resource, isAsync);
                
            } else {
                
                response = processRequest(t, client, t.getRequestBody(), resource, isAsync);
                
            }
            
            if(response == null) {
                serverError(t);
                return;
            }

            try {

                ResponseCode responseCode = (isAsync) ? response.getRedirectResponseCode() : response.getResponseCode();
                String responseBody = (isAsync) ? response.getRedirectResponse() : response.getResponse();

                switch (responseCode) {

                    case REQUEST_FAILED:
                        failRequest(t, responseBody);
                        break;
                    case FORBIDDEN:
                        authFailure(t);
                        break;
                    case TOO_MANY_REQUESTS:
                        rateLimited(t);
                        break;
                    case UNAUTHORIZED:
                        noApiKey(t);
                        break;
                    case SERVER_ERROR:
                        serverError(t);
                        break;
                    case SUCCESSFUL:
                        sendResponse(t, 200, responseBody);
                        break;

                }

            } catch (APIException ex) {

                System.out.println(ex.getMessage());
                serverError(t);
                
            }

        }

        private boolean checkParameters(String resourceStr, HashMap<String, String> input) {

            if(resources.getResource(resourceStr).getParameters().size() > 0) {

                APIResource resource = resources.getResource(resourceStr);
                int size = resource.getParameters().size();

                for(int i=0; i<size; i++) {

                    String key = resource.getParameters().get(i);
                    if(!input.containsKey(key))
                        return false;

                }

            }

            return true;
            
        }
        
        private APIResponse processRequest(HttpExchange t, RemoteClient client, InputStream bodyInput,
                                           String resource, String ipAddr, String port, String hostname, boolean isAsync) {

            Scanner scnr = new Scanner(bodyInput);

            String body = "";

            while(scnr.hasNextLine()) {
                body += scnr.nextLine();
            }

            scnr.close();

            if(RequestParser.isEmpty(body)) {
                failRequest(t, "Empty request body.");
                return null;
            }

            if(!RequestParser.verifyJson(body)) {
                failRequest(t, "Invalid JSON format.");
                return null;
            }


            JSONObject obj = RequestParser.parseJson(body, true);
            HashMap<String, String> map = obj;
            
            if(ipAddr != null) {
                
                ZeroTrustRequestType type = ZeroTrustRequestType.GET_RESOURCE;
                
                if(config.getSessionInitPath().equals(resource))
                    type = ZeroTrustRequestType.SESSION_INIT;
                else if(config.getSessionKeyTransferPath().equals(resource))
                    type = ZeroTrustRequestType.KEY_TRANSFER;
                else if(config.getSessionClosePath().equals(resource))
                    type = ZeroTrustRequestType.SESSION_CLOSE;
                
                map = decryptZeroTrust(obj, type);
                
            }
            
            if(map == null) {
                failRequest(t, "Missing or invalid parameters.");
                return null;
            }

            if(!checkParameters(resource, map)) {
                failRequest(t, "Missing parameters.");
                return null;
            }

            if(ipAddr != null) {

                if(client == null) {

                    String apiKey = t.getRequestHeaders().getFirst("X-Api-Key");
                    client = initAuthentication(apiKey, ipAddr, port, hostname, map);

                    if(client == RemoteClient.NONE) {
                        noApiKey(t);
                        return null;
                    }

                } else {

                    if (!isAuthenticated(client)) {
                        noApiKey(t);
                        return null;
                    }

                }

            } else {

                if (!isAuthenticated(client)) {
                    noApiKey(t);
                    return null;
                }

            }

            if(client.inBlacklist()) {
                authFailure(t);
                return null;
            }

            if(client.isLimited(config.getRequestsPerMinute())) {
                rateLimited(t);
                return null;
            }

            return (isAsync) ? asyncExecute(client, resource, map) : execute(client, resource, map);

        }
        
        private APIResponse processRequest(HttpExchange t, RemoteClient client, InputStream bodyInput, String resource, boolean isAsync) {

            Scanner scnr = new Scanner(bodyInput);

            String body = "";

            while(scnr.hasNextLine()) {
                body += scnr.nextLine();
            }

            scnr.close();

            if(RequestParser.isEmpty(body)) {
                failRequest(t, "Empty request body.");
                return null;
            }
            
            HashMap<String, String> map = parseRequestBody(client, resource, body);
            
            if(!checkParameters(resource, map)) {
                failRequest(t, "Missing parameters.");
                return null;
            }

            if(!isAuthenticated(client)) {
                noApiKey(t);
                return null;
            }

            if(client.inBlacklist()) {
                authFailure(t);
                return null;
            }

            if(client.isLimited(config.getRequestsPerMinute())) {
                rateLimited(t);
                return null;
            }
            
            return (isAsync) ? asyncExecute(client, resource, map) : execute(client, resource, map);
            
        }
        
        private APIResponse processRequest(HttpExchange t, RemoteClient client, String resource, String queryString, boolean isAsync) {
            
            HashMap<String, String> map = RequestParser.queryToMap(queryString);

            if(!checkParameters(resource, map)) {
                failRequest(t, "Missing parameters.");
                return null;
            }

            if(!isAuthenticated(client)) {
                noApiKey(t);
                return null;
            }

            if(client.inBlacklist()) {
                authFailure(t);
                return null;
            }

            if(client.isLimited(config.getRequestsPerMinute())) {
                rateLimited(t);
                return null;
            }

            return (isAsync) ? asyncExecute(client, resource, map) : execute(client, resource, map);
            
        }
        
        private void authFailure(HttpExchange t) {

            String retVal = "{\"request_status\":\"forbidden\",\"message\":\"Your network" +
                    " addresses will be blocked after a series of these attempts.\"}";
            sendResponse(t, 401, retVal);

        }

        private void rateLimited(HttpExchange t) {
            String retVal = "{\"request_status\":\"too_many_requests\"}";
            sendResponse(t, 429, retVal);
        }

        private void serverError(HttpExchange t) {

            String retVal = "{\"request_status\":\"server_error\"}";
            sendResponse(t, 500, retVal);

        }

        private void noApiKey(HttpExchange t) {

            String retVal = "{\"request_status\":\"unauthorized\"}";
            sendResponse(t, 401, retVal);

        }

        private void failRequest(HttpExchange t, String reason) {

            JSONObject retObj = new JSONObject();
            retObj.put("request_status", "fail");
            retObj.put("fail_reason", reason);

            String retVal = "{\"request_status\":\"fail\"}";
            int code = 500;

            try {
                retVal = JSON.getString(retObj);
                code = 400;
            } catch (Exception ex) {

            }

            sendResponse(t, code, retVal);

        }
        private void sendResponse(HttpExchange t, int code, String response) {

            try {

                t.sendResponseHeaders(code, response.length());
                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();

            } catch (Exception ex) {
                ex.printStackTrace();
            }

        }

    }

}
