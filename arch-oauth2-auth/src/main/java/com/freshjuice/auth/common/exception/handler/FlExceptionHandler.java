package com.freshjuice.auth.common.exception.handler;

import com.freshjuice.auth.common.constants.CommonConstants;
import com.freshjuice.auth.common.enums.JsonResultEnum;
import com.freshjuice.auth.common.exception.BizException;
import com.freshjuice.auth.common.vo.JsonResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;


@Slf4j
@ControllerAdvice
public class FlExceptionHandler {

    /**
     * Biz异常
     * @param ex
     * @return
     */
    @ExceptionHandler(BizException.class)
    @ResponseBody
    public JsonResult handlerBizException(BizException ex) {
        //ex.printStackTrace();
        log.error("业务异常: {}", ex.getMessage() , ex);
        return JsonResult.buildFailedResult(ex.getExceptionCodeWith(null), ex.getMessage());
    }


    /**
     * 参数校验异常
     * @param ex
     * @return
     */
    @ExceptionHandler(BindException.class)
    @ResponseBody
    public JsonResult handlerBindException(BindException ex) {
        //ex.printStackTrace();
        log.error("参数校验异常: {}", ex.getMessage(), ex);
        return JsonResult.buildFailedResult(JsonResultEnum.FAIL.getCode(),
                                            ex.getBindingResult().getFieldError().getDefaultMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseBody
    public JsonResult handlerValidateException(MethodArgumentNotValidException  ex) {
        //ex.printStackTrace();
        log.error("参数校验异常: {}", ex.getMessage(), ex);
        return JsonResult.buildFailedResult(JsonResultEnum.FAIL.getCode(),
                                            ex.getBindingResult().getFieldError().getDefaultMessage());
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseBody
    public JsonResult handlerArgTypeException(MethodArgumentTypeMismatchException ex) {
        //ex.printStackTrace();
        log.error("参数校验异常: {}", ex.getMessage(), ex);
        return JsonResult.buildFailedResult(JsonResultEnum.FAIL.getCode(), CommonConstants.ARG_TYPE_ERROR);
    }


    @ExceptionHandler(Exception.class)
    @ResponseBody
    public JsonResult exceptionHandler(Exception ex) {
        //ex.printStackTrace();
        log.error("系统异常: {}", ex.getMessage(), ex);
        return JsonResult.buildFailedResult(JsonResultEnum.FAIL.getCode(), CommonConstants.SYSTEM_ERROR);
    }

}
