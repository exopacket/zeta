package com.inteliense.trusty.server;

import java.util.ArrayList;

public class APIResources {

    private ArrayList<String> resources = new ArrayList<String>();
    private ArrayList<APIResource> definitions = new ArrayList<APIResource>();

    public ArrayList<String> getResourcesList() {
        return resources;
    }

    public int getIndex(String resource) {

        for(int i=0; i< resources.size(); i++) {
            if(resources.get(i).equals(resource))
                return i;
        }

        return -1;

    }

    public boolean inList(String resource) {
        for(int i=0; i< resources.size(); i++) {
            if(resources.get(i).equals(resource))
                return true;
        }

        return false;
    }

    public APIResource getResource(String value) {

        int index = getIndex(value);
        return definitions.get(index);

    }

    public void addResource(String path, APIResource definition) {

        resources.add(path.replace("/", "_"));
        definitions.add(definition);

    }

    public void addResource(String path, String[] parameters, APIResource definition) {

        resources.add(path.replace("/", "_"));
        definitions.add(definition);
        getResource(path.replace("/", "_")).setParameters(parameters);

    }

    public void addResource(String path, ArrayList<String> parameters, APIResource definition) {

        resources.add(path.replace("/", "_"));
        definitions.add(definition);
        getResource(path.replace("/", "_")).setParameters(parameters);

    }


}
