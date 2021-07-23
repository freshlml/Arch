package com.freshjuice.monomer.priority.entity;

import com.freshjuice.monomer.common.entity.BaseEntity;
import com.freshjuice.monomer.common.enums.ResourceTypeEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResourcePriority extends BaseEntity {
    private Long parentId;

    private String code;
    private String name;
    private ResourceTypeEnum type;
    private String url;
    private String authIf;
}
