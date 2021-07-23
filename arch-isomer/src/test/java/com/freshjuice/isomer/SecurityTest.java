package com.freshjuice.isomer;

import com.freshjuice.isomer.common.enums.ResourceTypeEnum;
import com.freshjuice.isomer.security.entity.*;
import com.freshjuice.isomer.security.service.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SecurityTest {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;
    
    @Autowired
    private UserRoleService userRoleService;

    @Autowired
    private ResourcePriorityService resourcePriorityService;

    @Autowired
    private RoleResourceService roleResourceService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //@Transactional
    @Test
    public void user() {

        User user1 = new User();
        user1.setUserName("di");
        user1.setPassword(bCryptPasswordEncoder.encode("ioc"));
        user1.setPhone("15623236821");
        userService.save(user1);

        User user2 = new User();
        user2.setUserName("dl");
        user2.setPassword(bCryptPasswordEncoder.encode("ioc"));
        user2.setPhone("1326191992");
        userService.save(user2);


        Role role1 = new Role();
        role1.setRoleCode("admin");
        role1.setRoleName("角色admin");
        roleService.save(role1);

        Role role2 = new Role();
        role2.setRoleCode("user");
        role2.setRoleName("角色user");
        roleService.save(role2);


        UserRole userRole1 = new UserRole();
        userRole1.setUserId(user1.getId());
        userRole1.setRoleId(role1.getId());
        userRole1.setRemark(user1.getUserName()+"拥有角色"+role1.getRoleCode());
        userRoleService.save(userRole1);

        UserRole userRole2 = new UserRole();
        userRole2.setUserId(user1.getId());
        userRole2.setRoleId(role2.getId());
        userRole2.setRemark(user1.getUserName()+"拥有角色"+role2.getRoleCode());
        userRoleService.save(userRole2);

        UserRole userRole3 = new UserRole();
        userRole3.setUserId(user2.getId());
        userRole3.setRoleId(role2.getId());
        userRole3.setRemark(user2.getUserName()+"拥有角色"+role2.getRoleCode());
        userRoleService.save(userRole3);


        ResourcePriority res1 = new ResourcePriority();
        res1.setCode("common");
        res1.setName("/common/**接口的权限");
        res1.setParentId(-1L);
        res1.setType(ResourceTypeEnum.DATA);
        res1.setUrl("/common/**");
        resourcePriorityService.save(res1);


        RoleResource roleRes1 = new RoleResource();
        roleRes1.setRoleId(role1.getId());
        roleRes1.setResourceId(res1.getId());
        roleRes1.setRemark("admin角色拥有common权限");
        roleResourceService.save(roleRes1);


    }





}
