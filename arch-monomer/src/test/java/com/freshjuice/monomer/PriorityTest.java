package com.freshjuice.monomer;

import com.freshjuice.monomer.common.enums.ResourceTypeEnum;
import com.freshjuice.monomer.priority.entity.ResourcePriority;
import com.freshjuice.monomer.priority.entity.User;
import com.freshjuice.monomer.priority.service.ResourcePriorityService;
import com.freshjuice.monomer.priority.service.UserService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class PriorityTest extends BaseJunitTest {

    @Autowired
    private UserService userService;

    @Autowired
    private ResourcePriorityService resourcePriorityService;

    @Test
    public void test() {
        User user = userService.getUserById(1L);
        //user = userService.getUserByName("di");
        //user = userService.getUserByPhone("15623236821");

        System.out.println("user");
    }

    @Test
    public void t1() {
        ResourcePriority resource = ResourcePriority.builder().code("test").name("test").type(ResourceTypeEnum.DATA).url("/test").authIf("0").build();
        resource.setId(100L);

        resourcePriorityService.save(resource);

        ResourcePriority one = resourcePriorityService.getByUrl("/test");

        System.out.println(one);

    }


    @Test
    public void t2() {

        List<ResourcePriority> result = resourcePriorityService.getResourcePriorities("di");

        System.out.println(result);
    }



}
