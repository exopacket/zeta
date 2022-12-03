package com.inteliense.zeta.server;

import com.inteliense.zeta.utils.EncodingUtils;
import com.inteliense.zeta.utils.JSON;
import com.inteliense.zeta.utils.RSA;
import com.inteliense.zeta.utils.SHA;
import com.sun.net.httpserver.*;
import org.json.simple.JSONObject;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public abstract class APIServer implements ClientFilter {

    // SESSION HIJACKING PREVENTION BY DYNAMIC API SECRET KEY ACROSS ONE OR MULTIPLE CLIENTS

    //                  SESSION INITIALIZATION REQUEST
    //----->            CLIENT SECURE RANDOM (48 BYTES)
    //----->    	 	HMAC512(input: original_secret_key, key: api_key)
    //----->    	 	AES-GCM(input: client_created_secret_key, key: first_32_bytes_client_random, iv: next_16_bytes_client_random)
    //AUTHORIZATION= 	SUMMATION OF THE TWO 64 bytes

    //                  SESSION INITIALIZATION RESPONSE
    //<-----            SERVER SECURE RANDOM (96 BYTES)
    //<-----    		HMAC512(input: client_created_secret_key, key: api_key)
    //<-----    		AES-CBC(input: server_created_secret_key, key: first_32_bytes_client_random, iv: secure_random)
    //AUTHORIZATION= 	SUMMATION OF THE TWO 64 bytes

    //                  SUBSEQUENT REQUESTS
    //----->    		HMAC512(input: server_created_secret_key, key: api_key)
    //----->    		AES-CBC(input: client_created_secret_key, key: first_32_bytes_client_random, iv: secure_random)
    //AUTHORIZATION= 	SUMMATION OF THE TWO 64 bytes

    //                  SUBSEQUENT RESPONSES
    //<-----    		HMAC512(input: client_created_secret_key, key: api_key)
    //<-----    		AES-CBC(input: server_created_secret_key, key: first_32_bytes_client_random, iv: secure_random)
    //AUTHORIZATION= 	SUMMATION OF THE TWO 64 bytes

    private APIServerConfig config;
    private APIResponseServer responseServer;
    private APIResources resources = new APIResources();
    private ArrayList<RemoteClient> clients = new ArrayList<RemoteClient>();
    private ArrayList<ClientSession> clientSessions = new ArrayList<ClientSession>();
    private ArrayList<APISession> pastSessions = new ArrayList<APISession>();
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

        if(config.getServerType() == APIServerType.ZERO_TRUST) {
            if(config.getZeroTrustSessionPaths()[0].equals("")) {
                throw new APIException("Server could not be started successfully. " +
                        "The API path is not set.");
            }
            if(config.getZeroTrustSessionPaths()[1].equals("")) {
                throw new APIException("Server could not be started successfully. " +
                        "The API path is not set.");
            }
            if(config.getZeroTrustSessionPaths()[2].equals("")) {
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

        startHttpsServer();

        switch(config.getServerResponseType()) {
            case REST_ASYNC:
            case ZERO_TRUST_ASYNC:
            case REST_HYBRID:
            case ZERO_TRUST_HYBRID:
                startResponseServer();
                break;
        }

    }
    public APIResource addResource(String value, APIResource definition) {
        resources.addResource(value, definition);
        return definition;
    }

    public APIResource addResource(String value, String[] parameters, APIResource definition) {
        resources.addResource(value, parameters, definition);
        return definition;
    }

    public APIResource addResource(String value, ArrayList<String> parameters, APIResource definition) {
        resources.addResource(value, parameters, definition);
        return definition;
    }

    public APIResource addResource(String value, boolean isAsync, APIResource definition) {
        boolean _isAsync = !(config.getServerResponseType() == APIServerType.REST_SYNC || config.getServerResponseType() == APIServerType.ZERO_TRUST_SYNC);
        if(_isAsync) resources.addResource(value, isAsync, definition);
        else resources.addResource(value, definition);
        return definition;
    }

    public APIResource addResource(String value, boolean isAsync, String[] parameters, APIResource definition) {
        boolean _isAsync = !(config.getServerResponseType() == APIServerType.REST_SYNC || config.getServerResponseType() == APIServerType.ZERO_TRUST_SYNC);
        if(_isAsync) resources.addResource(value, isAsync, parameters, definition);
        else resources.addResource(value, parameters, definition);
        return definition;
    }

    public APIResource addResource(String value, boolean isAsync, ArrayList<String> parameters, APIResource definition) {
        boolean _isAsync = !(config.getServerResponseType() == APIServerType.REST_SYNC || config.getServerResponseType() == APIServerType.ZERO_TRUST_SYNC);
        if(_isAsync) resources.addResource(value, isAsync, parameters, definition);
        else resources.addResource(value, parameters, definition);
        return definition;
    }

    public void addParameterToResource(String resource, String parameter) {
        resources.getResource(resource).addParameter(parameter);
    }

    public void setApiResources(APIResources apiResources) {
        resources = apiResources;
    }

    public ArrayList<ClientSession> getClientSessions() {
        return clientSessions;
    }

    public APIResources getApiResources() {
        return resources;
    }

    public void invalidateSession(ClientSession clientSession) {

        for(int i=clientSessions.size() - 1; i>=0; i--) {
            if(clientSessions.get(i).equals(clientSession)) {
                clientSession.getSession().deactivate();
                pastSessions.add(clientSession.getSession());
                clientSessions.remove(i);
            }
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

    public APIResponse asyncExecute(ClientSession clientSession, APIResource resource, Parameters parameters, RequestHeaders headers) {

        try {

            APIResponse mainResponse = getRedirectResponse(clientSession);

            Thread t = new Thread(() -> {
                addAsyncRequest(mainResponse);
                try {
                    APIResponse asyncResponse = resource.execute(clientSession, parameters, headers);
                    mainResponse.getAsyncRequest().requestComplete(asyncResponse);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    mainResponse.getAsyncRequest().requestComplete(new APIResponse(clientSession, ResponseCode.SERVER_ERROR));
                }
            });

            return mainResponse;

        } catch (APIException ex) {
            System.out.println(ex.getMessage());
        }

        return null;

    }

    public APIResponse getRedirectResponse(ClientSession clientSession) throws APIException {
        return new APIResponse(clientSession, ResponseCode.REDIRECT_START);
    }

    public void addAsyncRequest(APIResponse response) {
        responseServer.addRequest(response);
    }

    public abstract APIKeyPair lookupApiKeys(String apiKey);

    public abstract HashMap<String, String> getParameters(String reqBody, ContentType contentType);

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

    public ArrayList<RemoteClient> getClients() {
        return clients;
    }

    private void startResponseServer() throws APIException {

        responseServer = new APIResponseServer(config, this);

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

            APIKeyPair apiKeys = lookupApiKeys(headers.getString("X-Api-Key"));

            String reqBody = bodyFromStream(t.getRequestBody());

            if(!verifyRequestSignature(headers, t, reqBody, apiKeys)) {
                unauthorized(t);
                return;
            }

            int clientIndex = -1;

            if(headers.contains("X-Api-Session-Id")) {
                clientIndex = findClient(headers.getString("X-Api-Session-Id"));
            } else {
                clientIndex = findClient(apiKeys);
            }

            invalidateOldSessions();

            ClientSession clientSession = null;
            RemoteClient client = null;
            boolean skipVerification = false;

            if(clientIndex < 0) {

                try {

                    clientSession = appendNewClient(apiKeys, new ClientInfo(
                            headers, ipAddr, hostname
                    ));

                    client = clientSession.getClient();

                    if(!verifyApiAuthorization(headers, apiKeys, true)) {
                        invalidateSession(clientSession);
                        unauthorized(t);
                        return;
                    }

                } catch (Exception e) {
                    serverError(t);
                    return;
                }

            } else {

                client = clients.get(clientIndex);

                int clientSessionIndex = -1;

                if(headers.contains("X-Api-Session-Id")) {

                    clientSessionIndex = findClientSession(client, headers.getString("X-Api-Session-Id"));

                } else {

                    if (config.getZeroTrustSessionPaths()[0].equals(resource)) {

                        try {

                            APISession createdSession = new APISession(apiKeys, ipAddr,
                                    config.getServerType(),
                                    config.getMinutesTillInvalid());

                            clientSessionIndex = clientSessions.size();
                            clientSessions.add(new ClientSession(new ClientInfo(
                                    headers, remoteAddr, hostname
                            ), client, createdSession));

                            if(!verifyApiAuthorization(headers, apiKeys, true)) {
                                invalidateSession(clientSession);
                                unauthorized(t);
                                return;
                            }

                            skipVerification = true;

                        } catch (APIException e) {
                            serverError(t);
                            return;
                        }

                    } else {

                        clientSessionIndex = findClientSession(client, apiKeys);

                    }

                }

                if(clientSessionIndex < 0) {
                    unauthorized(t);
                    return;
                } else {
                    clientSession = clientSessions.get(clientSessionIndex);
                }

                if(!skipVerification) {

                    if (!verifyApiAuthorization(headers, apiKeys, true)) {
                        invalidateSession(clientSession);
                        unauthorized(t);
                        return;
                    }

                }

                if(!sessionAllowed(clientSession, apiKeys.getKey())) {
                    invalidateSession(clientSession);
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
                parameters = getParametersJson(t.getRequestURI());
            } else {

                if (headers.contains("Content-Type")) {

                    switch(headers.getString("Content-Type")) {
                        case "application/json":
                            parameters = getParametersJson(reqBody);
                            break;
                        case "application/xml":
                            parameters = getParameters(reqBody, ContentType.XML);
                            break;
                        case "text/html":
                            parameters = getParameters(reqBody, ContentType.HTML);
                            break;
                        case "text/plain":
                            parameters = getParameters(reqBody, ContentType.TEXT);
                            break;
                        default:
                            parameters = getParameters(reqBody, ContentType.UNKNOWN);
                            break;
                    }

                } else {

                    if(!JSON.verify(reqBody).equals("false"))
                        parameters = getParametersJson(reqBody);
                    else
                        parameters = getParameters(reqBody, ContentType.UNSET);

                }

            }

            boolean shouldCheckParams = resources.getResource(resource).getParameters().size() > 0;

            if(shouldCheckParams) {
                if(parameters == null) {
                    failRequest(t, "Invalid parameters.");
                    return;
                }
                if (!checkParameters(resource, parameters)) {
                    failRequest(t, "Invalid parameters.");
                    return;
                }
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
                response = processRequest(headers, clientSession, resource, parameters);
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
                    case SUCCESSFUL:
                        sendResponse(t, 200, responseBody, contentType, clientSession);
                        break;

                }

            } catch (Exception ex) {

                System.out.println(ex.getMessage());
                serverError(t);
                
            }

        }

        private void invalidateOldSessions() {
            for(int i=clientSessions.size() - 1; i>=0; i--) {
                if(clientSessions.get(i).getSession().invalidateByTime()) {
                    pastSessions.add(clientSessions.get(i).getSession());
                    clientSessions.remove(i);
                }
            }
        }

        private ClientSession appendNewClient(APIKeyPair keys, ClientInfo info) {

            return ClientSession.createClient(info, keys, APIServer.this);

        }

        private boolean verifyApiAuthorization(RequestHeaders headers, APIKeyPair apiKeys, boolean isNewSession) {

            if(config.useDynamicApiKey()) {

                String randomBytes = headers.getString("X-Api-Random-Bytes");
                String apiAuthorization = headers.getString("X-Api-Authorization");
                return (isNewSession) ?
                        apiKeys.initialInbound(apiAuthorization, randomBytes) :
                        apiKeys.inbound(apiAuthorization, randomBytes);

            } else { return true; }

        }

        private boolean verifyRequestSignature(RequestHeaders headers, HttpExchange t, String body, APIKeyPair apiKeys) {

            String urlPath = t.getRequestURI().getPath();

            System.out.println(urlPath);

            String timestamp = headers.getString("X-Request-Timestamp");
            String apiKey = apiKeys.getKey();
            String apiAuthorization = (config.useDynamicApiKey()) ?
                    headers.getString("X-Api-Authorization") :
                    apiKeys.getSecret();

            String value = apiAuthorization + urlPath + timestamp + body;
            String sig = SHA.getHmac384(value, apiKey);

            String sigReceived = headers.getString("X-Request-Signature");

            return sig.equals(sigReceived);

        }

        private boolean sessionAllowed(ClientSession client, String apiKey) {

            int numSessions = 0;

            for(int i=0; i<clientSessions.size(); i++) {

                RemoteClient currentClient = clientSessions.get(i).getClient();
                String clientApiKey = currentClient.getApiKey();
                
                if(apiKey.equals(clientApiKey)) {
                    numSessions++;
                    continue;
                }
                
                APISession currentSession = clientSessions.get(i).getSession();
                String sessionApiKey = currentSession.getApiKeys().getKey();
                
                if(apiKey.equals(sessionApiKey))
                    numSessions++;

            }

            return (numSessions >= config.getMaxSessions());

        }

        private int getNumSessions(RemoteClient client) {

            int numSessions = 0;

            for(int i=0; i<clientSessions.size(); i++) {

                RemoteClient current = clientSessions.get(i).getClient();
                if(current.equals(client))
                    numSessions++;

            }

            return numSessions;

        }

        private int findClientSession(RemoteClient client, String sessionId) {

            for(int i=0; i<clientSessions.size(); i++) {

                RemoteClient current = clientSessions.get(i).getClient();

                if(current.equals(client)) {

                    if(clientSessions.get(i).getSession().getSessionId().equals(sessionId))
                        return i;

                }

            }

            return -1;

        }

        private int findClientSession(RemoteClient client, APIKeyPair apiKeys) {

            for(int i=0; i<clientSessions.size(); i++) {

                RemoteClient current = clientSessions.get(i).getClient();

                if(current.equals(client)) {

                    if(clientSessions.get(i).getSession().getApiKeys().getKey().equals(apiKeys.getKey()))
                        return i;

                }

            }

            return -1;

        }

        private int findClient(APIKeyPair apiKeys) {

            for(int i=0; i<clients.size(); i++) {
                RemoteClient curr = clients.get(i);
                if(curr.equals(apiKeys))
                    return i;
            }

            return -1;

        }

        private int findClient(String sessionId) {

            for(int i=0; i<clients.size(); i++) {
                RemoteClient curr = clients.get(i);
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
                        || !headers.contains("X-Request-Signature")
                        || !headers.contains("X-Api-Session-Id")
                        || !headers.contains("X-Api-Key-Set-Id")
                        || !headers.contains("X-Api-User-Id")
                        || !headers.contains("X-Api-Client-Id")
                        || !headers.contains("X-Api-Session-Authorization")
                ) {
                    return false;
                }

                if(config.useDynamicApiKey() && (
                           !headers.contains("X-Api-Authorization")
                        || !headers.contains("X-Api-Random-Bytes"))) {
                    return false;
                }

            } else if(config.getServerType() == APIServerType.REST) {

                if(!headers.contains("X-Api-Key")
                        || !headers.contains("X-Request-Timestamp")
                        || !headers.contains("X-Request-Signature")) {
                    return false;
                }

            }

            return true;

        }

        private String bodyFromStream(InputStream bodyInput) {

            Scanner scnr = new Scanner(bodyInput);

            String body = "";

            while(scnr.hasNextLine()) {
                body += scnr.nextLine();
            }

            scnr.close();

            return body;

        }

        private HashMap<String, String> getParametersJson(String body) {

            if(RequestParser.isEmpty(body)) {
                return null;
            }

            if(!RequestParser.verifyJson(body)) {
                return null;
            }

            JSONObject obj = RequestParser.parseJson(body, true);
            HashMap<String, String> map = obj;

            return map;

        }

        private HashMap<String, String> getParametersJson(URI uri) {
            return RequestParser.queryToMap(uri.getQuery());
        }

        private APIResponse processRequest(RequestHeaders headers, ClientSession clientSession, String resourceName, HashMap<String, String> parameters) throws Exception {

            Parameters params = new Parameters(parameters);
            APIResource resource = resources.getResource(resourceName);

            if(config.getServerType() == APIServerType.ZERO_TRUST) {

                if(resource.isAsync()) {

                    if (config.getZeroTrustSessionPaths()[0].equals(resource.getName())) {
                        return processRequestZeroTrustAsync(clientSession, resource, params, headers, ZeroTrustRequestType.SESSION_INIT);
                    } else if (config.getZeroTrustSessionPaths()[1].equals(resource.getName())) {
                        return processRequestZeroTrustAsync(clientSession, resource, params, headers, ZeroTrustRequestType.KEY_TRANSFER);
                    } else if (config.getZeroTrustSessionPaths()[2].equals(resource.getName())) {

                        if(!isAuthenticated(headers, resource, params, clientSession)) {
                            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
                        }

                        return processRequestZeroTrustAsync(clientSession, resource, params, headers, ZeroTrustRequestType.SESSION_CLOSE);

                    } else {

                        if(!isAuthenticated(headers, resource, params, clientSession)) {
                            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
                        }

                        return processRequestZeroTrustAsync(clientSession, resource, params, headers, ZeroTrustRequestType.GET_RESOURCE);

                    }

                } else {

                    if (config.getZeroTrustSessionPaths()[0].equals(resource.getName())) {
                        return processRequestZeroTrustSync(clientSession, resource, params, headers, ZeroTrustRequestType.SESSION_INIT);
                    } else if (config.getZeroTrustSessionPaths()[1].equals(resource.getName())) {
                        return processRequestZeroTrustSync(clientSession, resource, params, headers, ZeroTrustRequestType.KEY_TRANSFER);
                    } else if (config.getZeroTrustSessionPaths()[2].equals(resource.getName())) {

                        if(!isAuthenticated(headers, resource, params, clientSession)) {
                            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
                        }

                        return processRequestZeroTrustSync(clientSession, resource, params, headers, ZeroTrustRequestType.SESSION_CLOSE);

                    } else {

                        if(!isAuthenticated(headers, resource, params, clientSession)) {
                            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
                        }

                        return processRequestZeroTrustAsync(clientSession, resource, params, headers, ZeroTrustRequestType.GET_RESOURCE);

                    }
                    
                }
                
            } else if(config.getServerType() == APIServerType.REST) {
                
                if(resource.isAsync()) {

                    if(!isAuthenticated(headers, resource, params, clientSession)) {
                        return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
                    }

                    return processRequestAsync(clientSession, resource, params, headers);
                    
                } else {

                    if(!isAuthenticated(headers, resource, params, clientSession)) {
                        return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
                    }
                    
                    return processRequestSync(clientSession, resource, params, headers);
                    
                }
                
            }
            
            return new APIResponse(clientSession, ResponseCode.SERVER_ERROR);

        }
        
        private APIResponse processRequestSync(ClientSession clientSession, APIResource resource, Parameters params, RequestHeaders headers) {
            APIResponse resp = execute(clientSession, resource, params, headers);
            return resp;
        }

        private APIResponse processRequestAsync(ClientSession clientSession, APIResource resource, Parameters params, RequestHeaders headers) {
            APIResponse resp = asyncExecute(clientSession, resource, params, headers);
            return resp;
        }

        private APIResponse processRequestZeroTrustSync(ClientSession clientSession, APIResource resource, Parameters params, RequestHeaders headers, ZeroTrustRequestType type) throws Exception {
            if(type == ZeroTrustRequestType.SESSION_INIT) {
                return initializeSession(clientSession);
            } else if(type == ZeroTrustRequestType.KEY_TRANSFER) {
                return keyTransfer(clientSession);
            } else if(type == ZeroTrustRequestType.SESSION_CLOSE) {
                return sessionClose(params, clientSession);
            } else if(type == ZeroTrustRequestType.GET_RESOURCE) {

                String encrypted = params.getString("ciphertext");

                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(getParametersJson(decrypted));

                APIResponse resp = execute(clientSession, resource, decryptedParams, headers);
                resp.encrypt();
                return resp;

            } else {

                String encrypted = params.getString("ciphertext");

                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(getParametersJson(decrypted));
                APIResponse resp = execute(clientSession, resource, decryptedParams, headers);
                resp.encrypt();
                return resp;

            }
        }

        private APIResponse processRequestZeroTrustAsync(ClientSession clientSession, APIResource resource, Parameters params, RequestHeaders headers, ZeroTrustRequestType type) throws Exception {

            if(type == ZeroTrustRequestType.SESSION_INIT ||
                    type == ZeroTrustRequestType.KEY_TRANSFER ||
                    type == ZeroTrustRequestType.SESSION_CLOSE) {
                return processRequestZeroTrustSync(clientSession, resource, params, headers, type);
            }

            String encrypted = params.getString("ciphertext");
            String keySetId = clientSession.getSession().getKeySetId();

            if(keySetId.equals(clientSession.getSession().getKeySetId())) {
                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(getParametersJson(decrypted));
                return asyncExecute(clientSession,
                        resource,
                        decryptedParams, headers);

            } else {

                return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);

            }

        }

        private APIResponse initializeSession(ClientSession clientSession) {

            JSONObject obj = new JSONObject();

            String sessionId = clientSession.getSession().getSessionId();

            obj.put("session_id", sessionId);
            obj.put("request_status", "success");

            return new APIResponse(clientSession, obj, ResponseCode.SUCCESSFUL);

        }

        private APIResponse keyTransfer(ClientSession clientSession) {

            JSONObject obj = new JSONObject();

            String randomBytes = clientSession.getSession().getRandomBytes();

            String serverPublicKey = EncodingUtils.getBase64(
                        clientSession
                            .getSession()
                            .getServerPublicKey()
                            .getPublicKey()
                            .getEncoded());

            String clientPrivateKey = EncodingUtils.getBase64(
                    clientSession
                            .getSession()
                            .getClientPrivateKey()
                            .getPrivateKey()
                            .getEncoded());

            String keySetId = clientSession
                    .getSession()
                    .getKeySetId();

            obj.put("random_bytes", randomBytes);
            obj.put("server_public_key", serverPublicKey);
            obj.put("client_private_key", clientPrivateKey);
            obj.put("key_set_id", keySetId);
            obj.put("request_status", "success");

            clientSession.getSession().keysTransferred();

            return new APIResponse(clientSession, obj, ResponseCode.SUCCESSFUL);

        }

        private APIResponse sessionClose(Parameters params, ClientSession clientSession) {

            String encrypted = params.getString("ciphertext");
            String keySetId = clientSession.getSession().getKeySetId();

            if(keySetId.equals(clientSession.getSession().getKeySetId())) {
                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(getParametersJson(decrypted));

                String receivedHash = decryptedParams.getString("authorization");
                String correctApiKey = clientSession.getSession().getApiKeys().getKey();
                String correctSecretKey = clientSession.getSession().getApiKeys().getSecret();
                String correctHash = SHA.getHmac384(SHA.get384(correctSecretKey), correctApiKey);

                if(correctHash.equals(receivedHash)) {
                    invalidateSession(clientSession);
                    JSONObject obj = new JSONObject();
                    obj.put("request_status", "success");
                    return new APIResponse(clientSession, obj, ResponseCode.SUCCESSFUL);
                }

            }

            return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);

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

        private void sendResponse(HttpExchange t, int code, String response, ContentType contentType, ClientSession clientSession) {

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

                if(config.getServerType() == APIServerType.ZERO_TRUST) {

                    t.getResponseHeaders().add(
                            "X-Api-Session-Authorization",
                            clientSession.getSession().getDynamicSessionAuth()
                    );

                    if(config.useDynamicApiKey()) {

                        t.getResponseHeaders().add(
                                "X-Api-Random-Bytes",
                                clientSession.getSession().getApiKeys().getOutboundIv()
                        );

                        //TODO
                        //FIXME
                        //For each session a client has open, create a header array of clients (clientId),
                        //timestamps (client's request time), and their respective api keys to use as the AES-CBC payload
                        //outbound to each client

                        if(getNumSessions(clientSession.getClient()) > 1) {

                            t.getResponseHeaders().add(
                                    "X-Api-Authorization",
                                    clientSession.getSession().getApiKeys().getOutboundSigningKey()
                            );

                            t.getResponseHeaders().add(
                                    "X-Server-Timestamp",
                                    String.valueOf(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC))
                            );

                            t.getResponseHeaders().add(
                                    "X-Client-Timestamp",
                                    clientSession.getSession().getApiKeys().getClientTimestamp()
                            );

                            t.getResponseHeaders().add(
                                    "X-Multi-Client-Id",
                                    clientSession.getSession().getApiKeys().getClientTimestamp()
                            );

                        } else {

                            t.getResponseHeaders().add(
                                    "X-Api-Authorization",
                                    clientSession.getSession().getApiKeys().getOutboundSigningKey()
                            );

                            t.getResponseHeaders().add(
                                    "X-Server-Timestamp",
                                    String.valueOf(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC))
                            );

                            t.getResponseHeaders().add(
                                    "X-Client-Timestamp",
                                    clientSession.getSession().getApiKeys().getClientTimestamp()
                            );

                        }

                    }

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
