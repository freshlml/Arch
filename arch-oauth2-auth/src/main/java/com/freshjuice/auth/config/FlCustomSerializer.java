package com.freshjuice.auth.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.type.ResolvedType;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.freshjuice.auth.common.bo.redis.RedisTestDto;
import com.freshjuice.auth.common.exception.BizException;
import com.freshjuice.auth.common.utils.JacksonUtils;
import lombok.extern.slf4j.Slf4j;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


@Slf4j
public class FlCustomSerializer {

    private ObjectMapper objectMapper = new ObjectMapper();
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    private static final byte[] EMPTY_ARRAY = new byte[0];
    private static final String EMPTY_STRING = "";

    public FlCustomSerializer() {//note: 使用和RedisTemplate相同的ObjectMapper
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        //objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        objectMapper.activateDefaultTyping(objectMapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
        objectMapper.registerModule(JacksonUtils.defaultJavaTimeModule());
    }
    public FlCustomSerializer(boolean withoutType) {
        if(!withoutType) {
            objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
            //objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            objectMapper.activateDefaultTyping(objectMapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
        }
        objectMapper.registerModule(JacksonUtils.defaultJavaTimeModule());
    }

    public Object deserialize(String value) {
        if(value == null || value.length() == 0) {
            return null;
        }
        try {
            return this.objectMapper.readValue(value, Object.class);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public <T> T deserialize(String value, Class<T> clz) {
        if(value == null || value.length() == 0) {
            return null;
        }
        try {
            return this.objectMapper.readValue(value, clz);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public <T> T deserialize(String value, TypeReference<T> type) {
        try {
            return this.objectMapper.readValue(value, type);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public <T> T deserialize(String value, JavaType type) {
        try {
            return this.objectMapper.readValue(value, type);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public Object deserialize(byte[] bytes) {
        if(bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return this.objectMapper.readValue(bytes, 0, bytes.length, Object.class);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public <T> T deserialize(byte[] bytes, Class<T> clz) {
        if(bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return this.objectMapper.readValue(bytes, 0, bytes.length, clz);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public <T> T deserialize(byte[] bytes, TypeReference<T> type) {
        if(bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return this.objectMapper.readValue(bytes, 0, bytes.length, type);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public <T> T deserialize(byte[] bytes, JavaType type) {
        if(bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return this.objectMapper.readValue(bytes, 0, bytes.length, type);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not read JSON: " + ex.getMessage());
        }
    }

    public String serialize(Object value) {
        if(value == null) {
            return EMPTY_STRING;
        }
        try {
            return this.objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not write JSON: " + ex.getMessage());
        }
    }

    public byte[] serializeAsBytes(Object value) {
        if(value == null) {
            return EMPTY_ARRAY;
        }
        try {
            return this.objectMapper.writeValueAsBytes(value);
        } catch (Exception ex) {
            throw new BizException(() -> "Could not write JSON: " + ex.getMessage());
        }
    }

    public static void main(String argv[]) {
        FlCustomSerializer flCustomSerializer = new FlCustomSerializer();

        BigInteger bi = new BigInteger("771123123123123123123213123213333333333333333333333333333333333313123123123123123213123123123123123123123121");
        BigDecimal bd = new BigDecimal("8.9999011231312312312323123123123123123123123123123123123123123123123123123234434541353453645364356421432423");
        RedisTestDto pojo = RedisTestDto.builder()
                .id(1234534535354L)
                .bl(false)
                .s(null)
                .name("just pojo哒哒哒")
                .bi(bi)
                .bd(bd)
                .pojoType("SYSTEM")
                .pojoTime(LocalDateTime.now())
                .build();
        List<RedisTestDto> list = new ArrayList<>();
        list.add(pojo);

        String serrString = flCustomSerializer.serialize(list);
        System.out.println(serrString);

        List<RedisTestDto> deSerrObj = flCustomSerializer.deserialize(serrString, new TypeReference<List<RedisTestDto>>() {});

        System.out.println(deSerrObj);


        List<RedisTestDto> deSerrObj2 = flCustomSerializer.deserialize(serrString, TypeFactory.defaultInstance().constructCollectionType(List.class, RedisTestDto.class));
        System.out.println(deSerrObj2);


    }


}
