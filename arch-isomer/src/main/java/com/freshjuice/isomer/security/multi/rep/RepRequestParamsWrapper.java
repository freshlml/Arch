package com.freshjuice.isomer.security.multi.rep;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.*;

public class RepRequestParamsWrapper extends HttpServletRequestWrapper {

    private final Map<String, String[]> cusParams = new HashMap<>();

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request The request to wrap
     * @throws IllegalArgumentException if the request is null
     */
    public RepRequestParamsWrapper(HttpServletRequest request) {
        super(request);
    }

    public void setParameter(String name, String val) {
        cusParams.put(name, new String[]{val});
    }
    public void setParameters(String name, String[] val) {
        cusParams.put(name, val);
    }

    /**
     * 先从cusParams取，如果存在，则返回(这将意味着可能覆盖super中的)，如果不存在，返回super
     * @param name
     * @return
     */
    @Override
    public String getParameter(String name) {
        String[] val = cusParams.get(name);
        return (val != null && val[0] != null) ? val[0] : super.getParameter(name);
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] val = cusParams.get(name);
        return (val != null && val.length > 0) ? val : super.getParameterValues(name);
    }

    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> mapParent = super.getParameterMap();
        if(mapParent == null) mapParent = new HashMap<>();
        cusParams.forEach(mapParent::put);
        return mapParent;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        Enumeration<String> keyParent = super.getParameterNames();
        Set<String> key = cusParams.keySet();
        if(key == null) key = new HashSet<>();
        while(keyParent.hasMoreElements()) {
            key.add(keyParent.nextElement());
        }
        Vector<String> vector = new Vector<>();
        vector.addAll(key);
        return vector.elements();
        /*Vector<String> vector = new Vector<>();
        Set<String> key = cusParams.keySet();
        if(key != null) key.stream().filter(name -> !vector.contains(name)).map(vector::add);
        Enumeration<String> keyParent = super.getParameterNames();
        while(keyParent.hasMoreElements()) {
            String el = keyParent.nextElement();
            if(!vector.contains(el)) vector.add(el);
        }
        return vector.elements();*/
    }

}
