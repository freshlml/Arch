package com.freshjuice.monomer.priority.service;

import com.freshjuice.monomer.priority.entity.ResourcePriority;

import java.util.List;


public interface ResourcePriorityService {
    ResourcePriority getByUrl(String url);
    List<ResourcePriority> getResourcePriorities(String userName);
    void save(ResourcePriority resource);
}
