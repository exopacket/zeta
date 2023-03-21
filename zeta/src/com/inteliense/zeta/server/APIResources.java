package com.inteliense.zeta.server;

import java.util.ArrayList;

public class APIResources {

    private ArrayList<String> resources = new ArrayList<String>();
    private ArrayList<APIResource> definitions = new ArrayList<APIResource>();

    public void removeAt(int index) {
        resources.remove(index);
        definitions.remove(index);
    }
    public ArrayList<String> getResourcesList() {
        return resources;
    }

    public int getSize() {
        return resources.size();
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

        resources.add(path);
        definitions.add(definition);

    }

    public void addResource(String path, String[] parameters, APIResource definition) {

        resources.add(path);
        definitions.add(definition);
        getResource(path).setParameters(parameters);

    }

    public void addResource(String path, ArrayList<String> parameters, APIResource definition) {

        resources.add(path);
        definitions.add(definition);
        getResource(path).setParameters(parameters);

    }

    public void addResource(String path, boolean isAsync, APIResource definition) {

        resources.add(path);
        definitions.add(definition);
        getResource(path).isAsync(isAsync);

    }

    public void addResource(String path, boolean isAsync, String[] parameters, APIResource definition) {

        resources.add(path);
        definitions.add(definition);
        getResource(path).setParameters(parameters);
        getResource(path).isAsync(isAsync);

    }

    public void addResource(String path, boolean isAsync, ArrayList<String> parameters, APIResource definition) {

        resources.add(path);
        definitions.add(definition);
        getResource(path).setParameters(parameters);
        getResource(path).isAsync(isAsync);

    }


}
