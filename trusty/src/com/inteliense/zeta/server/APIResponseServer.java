package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.JSON;
import com.sun.net.httpserver.*;
import org.json.simple.JSONObject;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;

public class APIResponseServer {

    private APIServerConfig config;
    private ArrayList<AsyncRequest> asyncRequests = new ArrayList<AsyncRequest>();
    private APIResources resources = new APIResources();
    private APIServer mainServer;

    public APIResponseServer(APIServerConfig config, APIServer mainServer) throws APIException {

        this.config = config;
        this.mainServer = mainServer;

        if(config.getResponseServerKeyPassword().equals("")) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The keystore password is not set.");
        }

        if(config.getResponseServerKeystorePath().equals("")) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The keystore path is not set.");
        }

        if(config.getApiPath().equals("")) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The API path is not set.");
        }

        File tmpFile = new File(config.getResponseServerKeystorePath());

        if(!tmpFile.exists()) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The keystore doesn't exist at " + config.getResponseServerKeystorePath());
        }

        tmpFile = null;

        startHttpsServer();

    }
    public void addRequest(APIResponse response) {
        asyncRequests.add(response.getAsyncRequest());
    }

    public APIResource addResource(String value, String[] parameters, APIResource definition) {
        resources.addResource(value, parameters, definition);
        return definition;
    }

    public void removeResource(int index) {
        resources.removeAt(index);
    }

    public APIResources getApiResources() {
        return resources;
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
            server.setExecutor(null);
            server.start();

        } catch (IOException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException |
                 CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();

        }

    }

    public APIResponse execute(ClientSession clientSession, APIResource resource, Parameters parameters, RequestHeaders headers) {
        try {
            return resource.execute(clientSession, parameters, headers);
        } catch (Exception ex) {
            ex.printStackTrace();
            return new APIResponse(clientSession, ResponseCode.SERVER_ERROR);
        }
    }
    public APIResponse processRequest(ClientSession clientSession, APIResource resource, Parameters params, RequestHeaders headers) throws Exception {

        if(!isAuthenticated(headers, resource, params, clientSession)) {
            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
        }

        int requestIndex = findAsyncRequest(resource.getName());
        if(requestIndex < 0) {
            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
        }
        AsyncRequest request = asyncRequests.get(requestIndex);

        if(!request.requestAuthVerifies(params.getString("authorization"))) {
            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
        }

        request.newPoll();

        if(request.isRequestComplete()) {
            APIResponse resp = request.getResponse();
            if(config.getServerType() == APIServerType.ZERO_TRUST)
                resp.encrypt();
            return resp;
        } else {

            return request.getContinue();

        }

    }

    private int findAsyncRequest(String resourceName) {
        for(int i=0; i<asyncRequests.size(); i++) {
            if(asyncRequests.get(i).getRequestId().equals(resourceName)) {
                return i;
            }
        }
        return -1;
    }

    private boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params, ClientSession clientSession) {

        if(!headers.getString("X-Api-Key").equals(clientSession.getSession().getApiKeys().getKey()))
            return false;

        if(!headers.getString("X-Api-Session-Id").equals(clientSession.getSession().getSessionId()))
            return false;

        return true;

    }

    private static class RequestParser {

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

    private boolean isBefore(LocalDateTime input, int secondsFromNow) {
        LocalDateTime limit = LocalDateTime.now().plusSeconds(secondsFromNow);
        return input.isBefore(limit);
    }
    private boolean isAfter(LocalDateTime input, int secondsFromNow) {
        LocalDateTime limit = LocalDateTime.now().minusSeconds(secondsFromNow);
        return input.isAfter(limit);
    }

    private class APIServerHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange t) throws IOException {

            final Headers headersObj = t.getRequestHeaders();
            final RequestHeaders headers = new RequestHeaders(headersObj);
            final String inboundRequestMethod = t.getRequestMethod().toUpperCase();

            String remoteAddr = t.getRemoteAddress().toString();
            String[] ipParts = remoteAddr.split(":");
            String leftSide = ipParts[0];
            //String port = ipParts[1];
            String[] leftParts = leftSide.split("/");
            String hostname = leftParts[0];
            String ipAddr = leftParts[1];

            String resource = t.getRequestURI().getPath()
                    .replace(config.getApiPath() + "/","")
                    .replace(config.getApiPath(), "");

            if(!RequestParser.verifyResource(getApiResources(), resource)) {
                failRequest(t, "Invalid resource.");
                return;
            }

            String requestMethod = getApiResources().getResource(resource).getRequestMethod();

            if(inboundRequestMethod.equals("OPTIONS")) {
                if(config.getCorsPolicy().isPermitted()) {
                    sendResponse(t, 200, "200-OPTIONS-SEND", ContentType.TEXT);
                    return;
                } else {
                    unauthorized(t);
                    return;
                }
            }

            if(!inboundRequestMethod.equals(requestMethod)) {
                failRequest(t, "Invalid request method.");
                return;
            }

            if(!checkRequestHeaders(headers)) {
                unauthorized(t);
                return;
            }

            if(
                    !isAfter(headers.getDateTimeFromTimestamp("X-Request-Timestamp"), 30) ||
                            !isBefore(headers.getDateTimeFromTimestamp("X-Request-Timestamp"), 30)
            ) {
                unauthorized(t);
                return;
            }

            APIKeyPair apiKeys = mainServer.lookupApiKeys(headers.getString("X-Api-Key"));

            int clientIndex = -1;

            if(headers.contains("X-Api-Session-Id")) {
                clientIndex = findClient(headers.getString("X-Api-Session-Id"));
            } else {
                clientIndex = findClient(apiKeys);
            }

            ClientSession clientSession = null;
            RemoteClient client = null;

            if(clientIndex < 0) {

                unauthorized(t);
                return;

            } else {

                client = mainServer.getClients().get(clientIndex);

                int clientSessionIndex = -1;

                if(headers.contains("X-Api-Session-Id")) {

                    clientSessionIndex = findClientSession(client, headers.getString("X-Api-Session-Id"));

                } else {
                    clientSessionIndex = findClientSession(client, apiKeys);
                }

                if(clientSessionIndex < 0) {
                    unauthorized(t);
                    return;
                } else {
                    clientSession = mainServer.getClientSessions().get(clientSessionIndex);
                }

                if(!sessionAllowed(clientSession, apiKeys.getKey())) {
                    mainServer.invalidateSession(clientSession);
                    unauthorized(t);
                    return;
                }

            }

            if(clientSession.getClient().isFlagged(headers, hostname)) {
                unauthorized(t);
                return;
            }

            clientSession.newRequest();

            HashMap<String, String> parameters;

            if(requestMethod.equals("GET")) {
                parameters = getParameters(t.getRequestURI());
            } else {
                unauthorized(t);
                return;
            }

            if(parameters == null) {
                failRequest(t, "Invalid parameters.");
                return;
            }
            if (!checkParameters(resource, parameters)) {
                failRequest(t, "Invalid parameters.");
                return;
            }

            if(client.inBlacklist()) {
                authFailure(t);
                return;
            }

            if(client.isLimited(config.getRequestsPerMinute())) {
                rateLimited(t);
                return;
            }

            APIResponse response = null;

            try {
                response = execute(clientSession, getApiResources().getResource(resource), new Parameters(parameters), headers);
            } catch (Exception e) {
                serverError(t);
                return;
            }

            try {

                ResponseCode responseCode = response.getResponseCode();
                String responseBody = response.getResponse();
                ContentType contentType = response.getContentType();

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
                        unauthorized(t);
                        break;
                    case SERVER_ERROR:
                        serverError(t);
                        break;
                    case REDIRECT_CONTINUE:
                    case SUCCESSFUL:
                        sendResponse(t, 200, responseBody, contentType);
                        break;
                    default:
                        failRequest(t, "unknown failure");

                }

            } catch (Exception ex) {

                System.out.println(ex.getMessage());
                serverError(t);

            }

        }

        private boolean sessionAllowed(ClientSession client, String apiKey) {

            int numSessions = 0;

            for(int i=0; i<mainServer.getClientSessions().size(); i++) {

                RemoteClient currentClient = mainServer.getClientSessions().get(i).getClient();
                String clientApiKey = currentClient.getApiKey();

                if(apiKey.equals(clientApiKey)) {
                    numSessions++;
                    continue;
                }

                APISession currentSession = mainServer.getClientSessions().get(i).getSession();
                String sessionApiKey = currentSession.getApiKeys().getKey();

                if(apiKey.equals(sessionApiKey))
                    numSessions++;

            }

            return (numSessions >= config.getMaxSessions());

        }
        private int findClientSession(RemoteClient client, String sessionId) {

            for(int i=0; i<mainServer.getClientSessions().size(); i++) {

                RemoteClient current = mainServer.getClientSessions().get(i).getClient();

                if(current.equals(client)) {

                    if(mainServer.getClientSessions().get(i).getSession().getSessionId().equals(sessionId))
                        return i;

                }

            }

            return -1;

        }

        private int findClientSession(RemoteClient client, APIKeyPair apiKeys) {

            for(int i=0; i<mainServer.getClientSessions().size(); i++) {

                RemoteClient current = mainServer.getClientSessions().get(i).getClient();

                if(current.equals(client)) {

                    if(mainServer.getClientSessions().get(i).getSession().getApiKeys().getKey().equals(apiKeys.getKey()))
                        return i;

                }

            }

            return -1;

        }

        private int findClient(APIKeyPair apiKeys) {

            for(int i=0; i<mainServer.getClients().size(); i++) {
                RemoteClient curr = mainServer.getClients().get(i);
                if(curr.equals(apiKeys))
                    return i;
            }

            return -1;

        }

        private int findClient(String sessionId) {

            for(int i=0; i<mainServer.getClients().size(); i++) {
                RemoteClient curr = mainServer.getClients().get(i);
                if(curr.equals(sessionId))
                    return i;
            }

            return -1;

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

        private boolean checkRequestHeaders(RequestHeaders headers) {

            if(config.getServerType() == APIServerType.ZERO_TRUST) {

                if(!headers.contains("X-Api-Key")
                        || !headers.contains("X-Request-Timestamp")
                        || !headers.contains("X-Api-Session-Id")
                ) {
                    return false;
                }

            } else if(config.getServerType() == APIServerType.REST) {

                if(!headers.contains("X-Api-Key")
                        || !headers.contains("X-Request-Timestamp")) {
                    return false;
                }

            }

            return true;

        }
        private HashMap<String, String> getParameters(URI uri) {
            return RequestParser.queryToMap(uri.getQuery());
        }

        private void authFailure(HttpExchange t) {

            String retVal = "{\"request_status\":\"forbidden\",\"message\":\"Your network" +
                    " addresses will be blocked after a series of these attempts.\"}";
            sendResponse(t, 401, retVal, ContentType.JSON);

        }

        private void rateLimited(HttpExchange t) {
            String retVal = "{\"request_status\":\"too_many_requests\"}";
            sendResponse(t, 429, retVal, ContentType.JSON);
        }

        private void serverError(HttpExchange t) {

            String retVal = "{\"request_status\":\"server_error\"}";
            sendResponse(t, 500, retVal, ContentType.JSON);

        }

        private void unauthorized(HttpExchange t) {

            String retVal = "{\"request_status\":\"unauthorized\"}";
            sendResponse(t, 401, retVal, ContentType.JSON);

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

            sendResponse(t, code, retVal, ContentType.JSON);

        }

        private void sendResponse(HttpExchange t, int code, String response, ContentType contentType) {

            try {

                if(config.getCorsPolicy().isPermitted()) {
                    t.getResponseHeaders().add("Access-Control-Allow-Origin",
                            config.getCorsPolicy().getCommaSeparated(
                                    config.getCorsPolicy().getOrigins()
                            ));
                    t.getResponseHeaders().add("Access-Control-Allow-RequestHeaders",
                            config.getCorsPolicy().getCommaSeparated(
                                    config.getCorsPolicy().getHeaders()
                            ));
                    t.getResponseHeaders().add("Access-Control-Allow-Methods",
                            config.getCorsPolicy().getCommaSeparated(
                                    config.getCorsPolicy().getMethods()
                            ));
                }

                String contentTypeStr = "";

                switch (contentType) {
                    case XML:
                        contentTypeStr = "application/xml";
                        break;
                    case HTML:
                        contentTypeStr = "text/html";
                        break;
                    case JSON:
                        contentTypeStr = "application/json";
                        break;
                    case TEXT:
                    default:
                        contentTypeStr = "text/plain";
                        break;
                }

                t.getResponseHeaders().add("Content-Type", contentTypeStr);
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
