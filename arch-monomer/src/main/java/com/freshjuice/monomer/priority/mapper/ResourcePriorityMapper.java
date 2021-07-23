package com.freshjuice.monomer.priority.mapper;

import com.freshjuice.monomer.priority.entity.ResourcePriority;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface ResourcePriorityMapper {
    ResourcePriority getByUrl(String url);
    void insert(ResourcePriority entity);
    List<ResourcePriority> listByIds(@Param("ids") List<Long> ids);
}
