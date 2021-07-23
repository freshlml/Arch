<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
${errorMsg }
<form action="/ArchMonomer/loginConfirm" method="post">
<TABLE>
<TR>
    <TD>用户名：</TD>
    <TD colSpan="2"><input type="text" id="usercode"
        name="username" style="WIDTH: 130px" /></TD>
</TR>
<TR>
    <TD>密 码：</TD>
    <TD><input type="password" id="pwd" name="password" style="WIDTH: 130px" />
    </TD>
</TR>
<TR>
    <TD></TD>
    <TD><input type="submit" value="提交" style="WIDTH: 130px" />
    </TD>
</TR>
</TABLE>
</form>

<form action="/ArchMonomer/phoneLogin/login" method="post">
    <TABLE>
        <TR>
            <TD>手机号：</TD>
            <TD colSpan="2"><input type="text"
                                   name="phoneNum" style="WIDTH: 130px" /></TD>
        </TR>
        <TR>
            <TD>验证码：</TD>
            <TD colSpan="2"><input type="text"
                                   name="phoneCredit" style="WIDTH: 130px" /></TD>
        </TR>
        <TR>
            <TD></TD>
            <TD><input type="submit" value="submit" style="WIDTH: 130px" />
            </TD>
        </TR>
    </TABLE>
</form>

</body>
</html>