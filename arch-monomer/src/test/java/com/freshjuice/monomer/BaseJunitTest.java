package com.freshjuice.monomer;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes={ApplicationConfig.class, ApplicationTextConfig.class, ApplicationMvcConfig.class})
@WebAppConfiguration("ROOT")
public class BaseJunitTest {
    private Logger logger = LoggerFactory.getLogger(BaseJunitTest.class);
    @Test
    public void test() {
        logger.info("idle test method avoid non method tests error");
    }

    /**
     * spring test 工业级实践
     */
}
