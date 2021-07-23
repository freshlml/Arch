<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<script type="text/javascript" src="${pageContext.request.contextPath }/statics/js/jquery-3.3.1.min.js"></script>
<title>主页</title>
</head>
<body>
<a href="${pageContext.request.contextPath }/pr1">pr1</a>
<a href="${pageContext.request.contextPath }/pr2">pr2</a>
<a href="/ArchMonomer/logout">logout</a>
</body>
<script type="text/javascript">
$(function() {
	$.ajax({
		type: 'POST',
		url: "/ArchMonomer/pr3",
		dataType: "JSON",
		success: function(data) {
			if(data.code == '403')
				alert(data.message);
			else {
				$("body").append(data.pr3);
			}
		},
		error: function(data) {
			if(data.code == '403')
				alert(data.message);
			else {
				$("body").append(data.pr3);
			}
		}
	});
});
</script>
</html>