<%@ page language="java" pageEncoding="utf-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%> 
<%
	pageContext.setAttribute("APP_PATH", request.getContextPath());
%>
<!DOCTYPE html>
<html lang="zh-CN">
  <head>
      <meta charset="utf-8">
	  <title>Secured主页</title>
	  <link href="${APP_PATH}/static/img/secured.jpg" rel="shortcut icon">
	  <link rel="stylesheet" href="${APP_PATH}/static/bootstrap/css/bootstrap.min.css">
	  <link rel="stylesheet" href="${APP_PATH}/static/css/style2.css">
	  <script src="${APP_PATH}/static/js/jquery-3.3.1.min.js"></script>
	  <script src="${APP_PATH}/static/bootstrap/js/bootstrap.min.js"></script>
  </head>
   <body>
        <%@include file="header.jsp" %>
        <div id="carousel-example-generic" class="carousel slide" data-ride="carousel">
            <!-- ol指示器  ol标签与ul标签不同 ol为是有序列表 ul为是无序列表 -->
            <ol class="carousel-indicators">
                  <!-- 指示器 -->
                <li data-target="#carousel-example-generic" data-slide-to="0" class="active"></li>
                <li data-target="#carousel-example-generic" data-slide-to="1"></li>
                <li data-target="#carousel-example-generic" data-slide-to="2"></li>
                <li data-target="#carousel-example-generic" data-slide-to="3"></li>
            </ol>

            <!-- 包装的轮播图片-->
            <div class="carousel-inner" role="listbox">
                <!--图片-->
                <div class="item active">
                    <img src="${APP_PATH}/static/img/1.jpg" alt="风景1">
                    <div class="carousel-caption">
                        <!--h4中的内容显示到图片上面，-->
                        <h4>真正的才智是刚毅的志向。 —— 拿破仑</h4>
                    </div>
                </div>
                <div class="item">
                    <img src="${APP_PATH}/static/img/2.jpg" alt="风景2">
                    <div class="carousel-caption">
                        <h4>志向不过是记忆的奴隶，生气勃勃地降生，但却很难成长。 —— 莎士比亚</h4>
                    </div>
                </div>
                <div class="item">
                    <img src="${APP_PATH}/static/img/5.jpg" alt="风景3">
                    <div class="carousel-caption">
                        <h4>但行好事，莫问前程。 —— 武文波</h4>
                    </div>
                </div>
                <div class="item">
                    <img src="${APP_PATH}/static/img/4.jpg" alt="风景4">
                    <div class="carousel-caption">
                        <h4>生活有度，人生添寿。 —— 书摘</h4>
                    </div>
                </div>
            </div>

            <!-- Controls -->
            <a class="left carousel-control" href="#carousel-example-generic" role="button" data-slide="prev">
                <span class="glyphicon glyphicon-chevron-left" aria-hidden="true"></span>
                <span class="sr-only">Previous</span>
            </a>
            <a class="right carousel-control" href="#carousel-example-generic" role="button" data-slide="next">
                <span class="glyphicon glyphicon-chevron-right" aria-hidden="true"></span>
                <span class="sr-only">Next</span>
            </a>
        </div>
       <div class="container">
       		<div class="row clearfix">
       			<div class="col-md-3 column">
					<h2>
						课程介绍
					</h2>
					<p style="text-indent: 200px">
						《大数据技术与应用》 是2018年教育部新增专业，2019已成为热门报考专业。数据是战略资源，大数据技术就是从数量庞大、结构复杂的数据中快速获得有价值信息的技术。大数据作为一个全新互联网的产业，正处于快速发展时期。预计2020年，我国大数据市场规模将超过8000亿元，有望成世界第一数据资源大国。预计到2022年市场规模将达千亿级。2025年中国将成为全球最大的数据圈。<a class="btn" href="#">更多 »</a>
					</p>
					<h2>
						联系我们
					</h2>
					<p>
						电话：18173516309<br/>
						邮箱：1046762075@qq.com
					</p>
				</div>
				<div class="col-md-7 col-md-offset-2 main">
					<h2>
                        数字电视原理相关书籍
					</h2>
					<p>
						<img src="${APP_PATH}/static/img/book1.jpg" height="200" width="150" />
                        <img src="${APP_PATH}/static/img/book4.jpg" height="200" width="150" />
                        <img src="${APP_PATH}/static/img/book3.jpg" height="200" width="150" />

					</p>
					<h3 class="text-info">最新文章</h3>
					<c:forEach items="${pageInfo.list }" var="news">
						<ul><li>
							<a href="${APP_PATH }/selectNewsById?id=<c:out value="${news.id}"/>"><c:out value="${news.title}"/></a>
							---------------------------------发布时间：<c:out value="${news.time}"/>
							<a href="${APP_PATH }/selectNewsById?id=<c:out value="${news.id}"/>"><i>阅读全文»»</i></a>
						</li></ul>
					</c:forEach>
					<ul class="pagination">
						<li>
							<c:if test="${pageInfo.hasPreviousPage}">
								<a href="${APP_PATH }/page/${pageInfo.pageNum-1}">Previous page</a>
							</c:if>
						</li>
						<li>
							<c:if test="${pageInfo.hasNextPage}">
								<a href="${APP_PATH }/page/${pageInfo.pageNum+1}">Next page</a>
							</c:if>
						</li>
					</ul>
				</div>
			</div>
	   </div>
     <%@include file="footer.jsp" %>
  </body>
</html>
