package com.freshjuice.monomer.priority.service.impl;

import com.freshjuice.monomer.priority.entity.ResourcePriority;
import com.freshjuice.monomer.priority.entity.RoleResource;
import com.freshjuice.monomer.priority.entity.User;
import com.freshjuice.monomer.priority.entity.UserRole;
import com.freshjuice.monomer.priority.mapper.ResourcePriorityMapper;
import com.freshjuice.monomer.priority.service.ResourcePriorityService;
import com.freshjuice.monomer.priority.service.RoleResourceService;
import com.freshjuice.monomer.priority.service.UserRoleService;
import com.freshjuice.monomer.priority.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ResourcePriorityServiceImpl implements ResourcePriorityService {

    @Autowired
    private ResourcePriorityMapper resourcePriorityMapper;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRoleService userRoleService;

    @Autowired
    private RoleResourceService roleResourceService;

    @Override
    public ResourcePriority getByUrl(String url) {
        if(url == null) return null;
        return resourcePriorityMapper.getByUrl(url);
    }

    @Override
    public List<ResourcePriority> getResourcePriorities(String userName) {
        List<ResourcePriority> result = new ArrayList<>();
        if(userName == null) return result;

        User user = userService.getUserByName(userName);
        if(user == null) return result;

        List<UserRole> userRoles = userRoleService.listByUserId(user.getId());
        List<Long> roleIds = userRoles.stream().map(userRole -> userRole.getRoleId()).collect(Collectors.toList());
        if(roleIds==null || roleIds.size()==0) return result;

        List<RoleResource> roleResources = roleResourceService.listByRoleIds(roleIds);
        List<Long> ids = roleResources.stream().map(roleResource -> roleResource.getResourceId()).distinct().collect(Collectors.toList());
        if(ids==null || ids.size()==0) return result;

        result = resourcePriorityMapper.listByIds(ids);

        //result = list.stream().collect(Collectors.groupingBy(ResourcePriority::getCode, Collectors.toList()));
        return result;
    }

    @Override
    public void save(ResourcePriority resource) {
        resourcePriorityMapper.insert(resource);
    }
}
