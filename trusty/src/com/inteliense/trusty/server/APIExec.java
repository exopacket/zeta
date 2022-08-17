package com.inteliense.trusty.server;

import java.util.HashMap;

public interface APIExec {

    APIResponse execute(RemoteClient client, HashMap<String, String> parameters);

}
