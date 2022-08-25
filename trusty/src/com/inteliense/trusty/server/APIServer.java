package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.EncodingUtils;
import com.inteliense.trusty.utils.JSON;
import com.inteliense.trusty.utils.RSA;
import com.inteliense.trusty.utils.SHA;
import com.sun.net.httpserver.*;
import org.json.simple.JSONObject;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.rmi.Remote;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

public abstract class APIServer implements ClientFilter {

    private APIServerConfig config;
    private APIResponseServer responseServer;
    private APIResources resources = new APIResources();
    private ArrayList<RemoteClient> clients = new ArrayList<RemoteClient>();
    private ArrayList<ClientSession> clientSessions = new ArrayList<ClientSession>();
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

    public APIResponse execute(ClientSession clientSession, APIResource resource, Parameters parameters) {
        return resource.execute(clientSession, parameters);
    }

    //TODO
    public APIResponse asyncExecute(ClientSession clientSession, APIResource resource, Parameters parameters) {

        try {

            APIResponse retVal = getRedirectResponse(clientSession, resource, parameters);

            Thread t = new Thread(() -> {
                resource.execute(clientSession, parameters);
                addAsyncRequest(clientSession, parameters, resource, retVal);
            });

            return retVal;

        } catch (APIException ex) {
            System.out.println(ex.getMessage());
        }

        return null;
        
    }

    public APIResponse getRedirectResponse(ClientSession clientSession, APIResource resource, Parameters parameters) throws APIException {

        return new APIResponse(clientSession, ResponseCode.REDIRECT_START);

    }

    public void addAsyncRequest(ClientSession clientSession, Parameters parameters, APIResource resource, APIResponse response) {
        responseServer.addRequest(clientSession, parameters, resource, response);
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

    private void startResponseServer() {



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

            final Headers headers = t.getRequestHeaders();
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
                    noApiKey(t);
                    return;
                }
            }

            if(!inboundRequestMethod.equals(requestMethod)) {
                failRequest(t, "Invalid request method.");
                return;
            }

            if(!checkHeaders(headers)) {
                noApiKey(t);
                return;
            }

            APIKeyPair apiKeys = lookupApiKeys(headers.getFirst("X-Api-Key"));

            String reqBody = bodyFromStream(t.getRequestBody());

            if(!verifyRequestSignature(headers, t, reqBody, apiKeys)) {
                noApiKey(t);
                return;
            }

            int clientIndex = -1;

            if(headers.containsKey("X-Api-Session-Id")) {
                clientIndex = findClient(headers.getFirst("X-Api-Session-Id"));

            } else {
                clientIndex = findClient(apiKeys);
            }

            ClientSession clientSession = null;
            RemoteClient client = null;

            if(clientIndex < 0) {
                try {
                    clientSession = appendNewClient(apiKeys, new ClientInfo(
                            headers, ipAddr, Integer.parseInt(port), hostname
                    ));
                    client = clientSession.getClient();
                } catch (Exception e) {
                    serverError(t);
                    return;
                }
            } else {
                client = clients.get(clientIndex);
                APISession session = client.getSession(headers.getFirst("X-Api-Session-Id"));
                clientSession = new ClientSession(client, session);
            }

            clientSession.getSession().newRequest();

            HashMap<String, String> parameters;

            if(requestMethod.equals("GET")) {
                parameters = _getParameters(t.getRequestURI());
            } else {

                if (headers.containsKey("Content-Type")) {

                    switch(headers.getFirst("Content-Type")) {
                        case "application/json":
                            parameters = _getParameters(reqBody);
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
                        parameters = _getParameters(reqBody);
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
            boolean isAsync = resources.getResource(resource).isAsync();

            try {

                ResponseCode responseCode = ResponseCode.SUCCESSFUL;//(isAsync) ? response.getRedirectResponseCode() : response.getResponseCode();
                String responseBody = "";//(isAsync) ? response.getRedirectResponse() : response.getResponse();
                ContentType contentType = ContentType.TEXT;//(isAsync) ? ContentType.JSON : response.getContentType();

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
                        sendResponse(t, 200, responseBody, contentType);
                        break;

                }

            } catch (Exception ex) {

                System.out.println(ex.getMessage());
                serverError(t);
                
            }

        }

        private ClientSession appendNewClient(APIKeyPair keys, ClientInfo info) {

            return ClientSession.createClient(info, keys, APIServer.this);

        }

        private boolean verifyRequestSignature(Headers headers, HttpExchange t, String body, APIKeyPair apiKeys) {
            String urlPath = t.getRequestURI().getPath();
            System.out.println(urlPath);
            String timestamp = headers.getFirst("X-Request-Timestamp");
            String apiKey = apiKeys.getKey();
            String apiSecret = apiKeys.getSecret();

            String key = apiKey + ";" + urlPath + ";" + timestamp + ";" + body;
            String sig = SHA.getHmac384(apiSecret, key);

            String sigReceived = headers.getFirst("X-Request-Signature");

            return sig.equals(sigReceived);
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

        private boolean checkHeaders(Headers headers) {

            if(config.getServerType() == APIServerType.ZERO_TRUST) {

                if(!headers.containsKey("X-Api-Key")
                        || !headers.containsKey("X-Request-Timestamp")
                        || !headers.containsKey("X-Request-Signature")
                        || !headers.containsKey("X-Api-Session-Id")
                        || !headers.containsKey("X-Api-Server-Public-Key")
                        || !headers.containsKey("X-Api-Client-Public-Key")
                        || !headers.containsKey("X-Api-User-Id")
                        || !headers.containsKey("X-Api-Client-Id")
                        || !headers.containsKey("X-Api-Session-Authorization")
                ) {
                    return false;
                }

            } else if(config.getServerType() == APIServerType.REST) {

                if(!headers.containsKey("X-Api-Key")
                        || !headers.containsKey("X-Request-Timestamp")
                        || !headers.containsKey("X-Request-Signature")) {
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

        private HashMap<String, String> _getParameters(String body) {

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

        private HashMap<String, String> _getParameters(URI uri) {
            return RequestParser.queryToMap(uri.getQuery());
        }

        private APIResponse processRequest(Headers headers, ClientSession clientSession, String resourceName, HashMap<String, String> parameters) throws Exception {

            Parameters params = new Parameters(parameters);
            APIResource resource = resources.getResource(resourceName);

            if(!isAuthenticated(headers, resource, params, clientSession)) {
                return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);
            }

            if(config.getServerType() == APIServerType.ZERO_TRUST) {

                if(resource.isAsync()) {

                    if (config.getZeroTrustSessionPaths()[0].equals(resource.getName())) {
                        return processRequestZeroTrustAsync(clientSession, resource, params, ZeroTrustRequestType.SESSION_INIT);
                    } else if (config.getZeroTrustSessionPaths()[1].equals(resource.getName())) {
                        return processRequestZeroTrustAsync(clientSession, resource, params, ZeroTrustRequestType.KEY_TRANSFER);
                    } else if (config.getZeroTrustSessionPaths()[2].equals(resource.getName())) {
                        return processRequestZeroTrustAsync(clientSession, resource, params, ZeroTrustRequestType.SESSION_CLOSE);
                    } else {
                        return processRequestZeroTrustAsync(clientSession, resource, params, ZeroTrustRequestType.GET_RESOURCE);
                    }

                } else {

                    if (config.getZeroTrustSessionPaths()[0].equals(resource.getName())) {
                        return processRequestZeroTrustSync(clientSession, resource, params, ZeroTrustRequestType.SESSION_INIT);
                    } else if (config.getZeroTrustSessionPaths()[1].equals(resource.getName())) {
                        return processRequestZeroTrustSync(clientSession, resource, params, ZeroTrustRequestType.KEY_TRANSFER);
                    } else if (config.getZeroTrustSessionPaths()[2].equals(resource.getName())) {
                        return processRequestZeroTrustSync(clientSession, resource, params, ZeroTrustRequestType.SESSION_CLOSE);
                    } else {
                        return processRequestZeroTrustAsync(clientSession, resource, params, ZeroTrustRequestType.GET_RESOURCE);
                    }
                    
                }
                
            } else if(config.getServerType() == APIServerType.REST) {
                
                if(resource.isAsync()) {

                    return processRequestAsync(clientSession, resource, params);
                    
                } else {
                    
                    return processRequestSync(clientSession, resource, params);
                    
                }
                
            }
            
            return new APIResponse(clientSession, ResponseCode.SERVER_ERROR);

        }
        
        private APIResponse processRequestSync(ClientSession clientSession, APIResource resource, Parameters params) {
            APIResponse resp = execute(clientSession, resource, params);
            return resp;
        }

        private APIResponse processRequestAsync(ClientSession clientSession, APIResource resource, Parameters params) {
            APIResponse resp = asyncExecute(clientSession, resource, params);
            return resp;
        }

        private APIResponse processRequestZeroTrustSync(ClientSession clientSession, APIResource resource, Parameters params, ZeroTrustRequestType type) throws Exception {
            if(type == ZeroTrustRequestType.SESSION_INIT) {
                return initializeSession(clientSession);
            } else if(type == ZeroTrustRequestType.KEY_TRANSFER) {
                return keyTransfer(clientSession);
            } else if(type == ZeroTrustRequestType.SESSION_CLOSE) {
                return sessionClose(clientSession);
            } else if(type == ZeroTrustRequestType.GET_RESOURCE) {

                String encrypted = params.getString("rsa_value");

                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(_getParameters(decrypted));

                APIResponse resp = execute(clientSession, resource, decryptedParams);
                resp.encrypt();
                return resp;

            } else {

                String encrypted = params.getString("rsa_value");

                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(_getParameters(decrypted));
                APIResponse resp = execute(clientSession, resource, decryptedParams);
                resp.encrypt();
                return resp;

            }
        }

        private APIResponse processRequestZeroTrustAsync(ClientSession clientSession, APIResource resource, Parameters params, ZeroTrustRequestType type) throws Exception {

            if(type == ZeroTrustRequestType.SESSION_INIT ||
                    type == ZeroTrustRequestType.KEY_TRANSFER ||
                    type == ZeroTrustRequestType.SESSION_CLOSE) {
                return processRequestZeroTrustSync(clientSession, resource, params, type);
            }

            String encrypted = params.getString("rsa_value");
            String keySetId = clientSession.getSession().getKeySetId();

            if(keySetId.equals(clientSession.getSession().getKeySetId())) {
                String decrypted = RSA.decrypt(
                        encrypted, clientSession
                                .getSession()
                                .getServerPrivateKey()
                                .getPrivateKey());

                Parameters decryptedParams = new Parameters(_getParameters(decrypted));
                return asyncExecute(clientSession, resource, decryptedParams);

            } else {

                return new APIResponse(clientSession, ResponseCode.UNAUTHORIZED);

            }

        }

        private APIResponse initializeSession(ClientSession clientSession) {

            JSONObject obj = new JSONObject();

            String sessionId = clientSession.getSession().getSessionId();
            String sessionAuth = clientSession.getSession().getSessionAuth();

            obj.put("session_auth", sessionAuth);
            obj.put("session_id", sessionId);
            obj.put("request_status", "success");
            obj.put("created_session", true);

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

        private APIResponse sessionClose(ClientSession clientSession) {

            clientSession.getSession().deactivate();
            JSONObject obj = new JSONObject();
            obj.put("request_status", "success");
            return new APIResponse(clientSession, obj, ResponseCode.SUCCESSFUL);

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

        private void noApiKey(HttpExchange t) {

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
                    t.getResponseHeaders().add("Access-Control-Allow-Headers",
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
