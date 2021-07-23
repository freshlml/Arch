package com.freshjuice.monomer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * top package
 * @author freshJuice
 */
public class ArchMonomer {
	public static void main(String argv[]) throws Exception {
		
		//logback test
		Logger logger = LoggerFactory.getLogger(ArchMonomer.class);
		logger.debug("commons logging slf4j logback");
		logger.info("commons logging slf4j logback");
		logger.warn("commons logging slf4j logback");
		logger.error("commons logging slf4j logback");
		
		
	}
	
	
}
