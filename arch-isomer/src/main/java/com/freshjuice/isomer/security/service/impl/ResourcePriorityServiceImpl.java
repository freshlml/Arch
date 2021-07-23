package com.freshjuice.isomer.security.service.impl;


import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.freshjuice.isomer.security.entity.ResourcePriority;
import com.freshjuice.isomer.security.mapper.ResourcePriorityMapper;
import com.freshjuice.isomer.security.service.ResourcePriorityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ResourcePriorityServiceImpl extends ServiceImpl<ResourcePriorityMapper, ResourcePriority> implements ResourcePriorityService {

    @Autowired
    private ResourcePriorityMapper resourcePriorityMapper;

}
