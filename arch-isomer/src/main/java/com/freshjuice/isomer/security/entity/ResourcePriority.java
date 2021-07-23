package com.freshjuice.isomer.security.entity;

import com.freshjuice.isomer.common.entity.BaseEntity;
import com.freshjuice.isomer.common.enums.ResourceTypeEnum;
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
public class ResourcePriority extends BaseEntity<Long> {
    private Long parentId;

    private String code;
    private String name;
    private ResourceTypeEnum type;
    private String url;
}
