/*
 Navicat Premium Data Transfer

 Source Server         : Nay
 Source Server Type    : MySQL
 Source Server Version : 50729
 Source Host           : localhost:3306
 Source Schema         : video

 Target Server Type    : MySQL
 Target Server Version : 50729
 File Encoding         : 65001

 Date: 11/10/2020 02:07:52
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for t_answer
-- ----------------------------
DROP TABLE IF EXISTS `t_answer`;
CREATE TABLE `t_answer`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `content` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `answeruser` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `pubtime2` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `topicId` int(11) NOT NULL,
  `state2` int(11) NULL DEFAULT 1,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `FKC06B980D29D8874D`(`topicId`) USING BTREE,
  CONSTRAINT `FKC06B980D29D8874D` FOREIGN KEY (`topicId`) REFERENCES `t_topic` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for t_news
-- ----------------------------
DROP TABLE IF EXISTS `t_news`;
CREATE TABLE `t_news`  (
  `id` int(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `article` text CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
  `time` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of t_news
-- ----------------------------
INSERT INTO `t_news` VALUES (1, '客户端 session 导致的安全问题', '<p>在Web中，session是认证用户身份的凭证，它具备如下几个特点：</p>\r\n\r\n<ol>\r\n	<li>用户不可以任意篡改</li>\r\n	<li>A用户的session无法被B用户获取</li>\r\n</ol>\r\n\r\n<p>也就是说，session的设计目的是为了做用户身份认证。但是，很多情况下，session被用作了别的用途，将产生一些安全问题，我们今天就来谈谈&ldquo;客户端session&rdquo;（client session）导致的安全问题。</p>\r\n\r\n<h2>0x01 什么是客户端session</h2>\r\n\r\n<p>在传统PHP开发中，<code>$_SESSION</code>变量的内容默认会被保存在服务端的一个文件中，通过一个叫&ldquo;PHPSESSID&rdquo;的Cookie来区分用户。这类session是&ldquo;服务端session&rdquo;，用户看到的只是session的名称（一个随机字符串），其内容保存在服务端。</p>\r\n\r\n<p>然而，并不是所有语言都有默认的session存储机制，也不是任何情况下我们都可以向服务器写入文件。所以，很多Web框架都会另辟蹊径，比如Django默认将session存储在数据库中，而对于flask这里并不包含数据库操作的框架，就只能将session存储在cookie中。</p>\r\n\r\n<p>因为cookie实际上是存储在客户端（浏览器）中的，所以称之为&ldquo;客户端session&rdquo;。</p>\r\n\r\n<h2>0x02 保护客户端session</h2>\r\n\r\n<p>将session存储在客户端cookie中，最重要的就是解决session不能被篡改的问题。</p>\r\n\r\n<p>我们看看flask是如何处理的：</p>\r\n\r\n<pre>\r\n<code>class SecureCookieSessionInterface(SessionInterface):\r\n    &quot;&quot;&quot;The default session interface that stores sessions in signed cookies\r\n    through the :mod:`itsdangerous` module.\r\n    &quot;&quot;&quot;\r\n    #: the salt that should be applied on top of the secret key for the\r\n    #: signing of cookie based sessions.\r\n    salt = &#39;cookie-session&#39;\r\n    #: the hash function to use for the signature. The default is sha1\r\n    digest_method = staticmethod(hashlib.sha1)\r\n    #: the name of the itsdangerous supported key derivation. The default\r\n    #: is hmac.\r\n    key_derivation = &#39;hmac&#39;\r\n    #: A python serializer for the payload. The default is a compact\r\n    #: JSON derived serializer with support for some extra Python types\r\n    #: such as datetime objects or tuples.\r\n    serializer = session_json_serializer\r\n    session_class = SecureCookieSession\r\n\r\n    def get_signing_serializer(self, app):\r\n        if not app.secret_key:\r\n            return None\r\n        signer_kwargs = dict(\r\n            key_derivation=self.key_derivation,\r\n            digest_method=self.digest_method\r\n        )\r\n        return URLSafeTimedSerializer(app.secret_key, salt=self.salt,\r\n                                      serializer=self.serializer,\r\n                                      signer_kwargs=signer_kwargs)\r\n\r\n    def open_session(self, app, request):\r\n        s = self.get_signing_serializer(app)\r\n        if s is None:\r\n            return None\r\n        val = request.cookies.get(app.session_cookie_name)\r\n        if not val:\r\n            return self.session_class()\r\n        max_age = total_seconds(app.permanent_session_lifetime)\r\n        try:\r\n            data = s.loads(val, max_age=max_age)\r\n            return self.session_class(data)\r\n        except BadSignature:\r\n            return self.session_class()\r\n\r\n    def save_session(self, app, session, response):\r\n        domain = self.get_cookie_domain(app)\r\n        path = self.get_cookie_path(app)\r\n        # Delete case. If there is no session we bail early.\r\n        # If the session was modified to be empty we remove the\r\n        # whole cookie.\r\n        if not session:\r\n            if session.modified:\r\n                response.delete_cookie(app.session_cookie_name,\r\n                                       domain=domain, path=path)\r\n            return\r\n        # Modification case. There are upsides and downsides to\r\n        # emitting a set-cookie header each request. The behavior\r\n        # is controlled by the :meth:`should_set_cookie` method\r\n        # which performs a quick check to figure out if the cookie\r\n        # should be set or not. This is controlled by the\r\n        # SESSION_REFRESH_EACH_REQUEST config flag as well as\r\n        # the permanent flag on the session itself.\r\n        if not self.should_set_cookie(app, session):\r\n            return\r\n        httponly = self.get_cookie_httponly(app)\r\n        secure = self.get_cookie_secure(app)\r\n        expires = self.get_expiration_time(app, session)\r\n        val = self.get_signing_serializer(app).dumps(dict(session))\r\n        response.set_cookie(app.session_cookie_name, val,\r\n                            expires=expires, httponly=httponly,\r\n                            domain=domain, path=path, secure=secure)\r\n</code></pre>\r\n\r\n<p>主要看最后两行代码，新建了<code>URLSafeTimedSerializer</code>类 ，用它的<code>dumps</code>方法将类型为字典的session对象序列化成字符串，然后用<code>response.set_cookie</code>将最后的内容保存在cookie中。</p>\r\n\r\n<p>那么我们可以看一下<code>URLSafeTimedSerializer</code>是做什么的：</p>\r\n\r\n<pre>\r\n<code>class Signer(object):\r\n    # &hellip;\r\n    def sign(self, value):\r\n        &quot;&quot;&quot;Signs the given string.&quot;&quot;&quot;\r\n        return value + want_bytes(self.sep) + self.get_signature(value)\r\n\r\n    def get_signature(self, value):\r\n        &quot;&quot;&quot;Returns the signature for the given value&quot;&quot;&quot;\r\n        value = want_bytes(value)\r\n        key = self.derive_key()\r\n        sig = self.algorithm.get_signature(key, value)\r\n        return base64_encode(sig)\r\n\r\n\r\nclass Serializer(object):\r\n    default_serializer = json\r\n    default_signer = Signer\r\n    # &hellip;.\r\n    def dumps(self, obj, salt=None):\r\n        &quot;&quot;&quot;Returns a signed string serialized with the internal serializer.\r\n        The return value can be either a byte or unicode string depending\r\n        on the format of the internal serializer.\r\n        &quot;&quot;&quot;\r\n        payload = want_bytes(self.dump_payload(obj))\r\n        rv = self.make_signer(salt).sign(payload)\r\n        if self.is_text_serializer:\r\n            rv = rv.decode(&#39;utf-8&#39;)\r\n        return rv\r\n\r\n    def dump_payload(self, obj):\r\n        &quot;&quot;&quot;Dumps the encoded object. The return value is always a\r\n        bytestring. If the internal serializer is text based the value\r\n        will automatically be encoded to utf-8.\r\n        &quot;&quot;&quot;\r\n        return want_bytes(self.serializer.dumps(obj))\r\n\r\n\r\nclass URLSafeSerializerMixin(object):\r\n    &quot;&quot;&quot;Mixed in with a regular serializer it will attempt to zlib compress\r\n    the string to make it shorter if necessary. It will also base64 encode\r\n    the string so that it can safely be placed in a URL.\r\n    &quot;&quot;&quot;\r\n    def load_payload(self, payload):\r\n        decompress = False\r\n        if payload.startswith(b&#39;.&#39;):\r\n            payload = payload[1:]\r\n            decompress = True\r\n        try:\r\n            json = base64_decode(payload)\r\n        except Exception as e:\r\n            raise BadPayload(&#39;Could not base64 decode the payload because of &#39;\r\n                &#39;an exception&#39;, original_error=e)\r\n        if decompress:\r\n            try:\r\n                json = zlib.decompress(json)\r\n            except Exception as e:\r\n                raise BadPayload(&#39;Could not zlib decompress the payload before &#39;\r\n                    &#39;decoding the payload&#39;, original_error=e)\r\n        return super(URLSafeSerializerMixin, self).load_payload(json)\r\n\r\n    def dump_payload(self, obj):\r\n        json = super(URLSafeSerializerMixin, self).dump_payload(obj)\r\n        is_compressed = False\r\n        compressed = zlib.compress(json)\r\n        if len(compressed) &lt; (len(json) - 1):\r\n            json = compressed\r\n            is_compressed = True\r\n        base64d = base64_encode(json)\r\n        if is_compressed:\r\n            base64d = b&#39;.&#39; + base64d\r\n        return base64d\r\n\r\n\r\nclass URLSafeTimedSerializer(URLSafeSerializerMixin, TimedSerializer):\r\n    &quot;&quot;&quot;Works like :class:`TimedSerializer` but dumps and loads into a URL\r\n    safe string consisting of the upper and lowercase character of the\r\n    alphabet as well as ``&#39;_&#39;``, ``&#39;-&#39;`` and ``&#39;.&#39;``.\r\n    &quot;&quot;&quot;\r\n    default_serializer = compact_json\r\n</code></pre>\r\n\r\n<p>主要关注<code>dump_payload</code>、<code>dumps</code>，这是序列化session的主要过程。</p>\r\n\r\n<p>可见，序列化的操作分如下几步：</p>\r\n\r\n<ol>\r\n	<li>json.dumps 将对象转换成json字符串，作为数据</li>\r\n	<li>如果数据压缩后长度更短，则用zlib库进行压缩</li>\r\n	<li>将数据用base64编码</li>\r\n	<li>通过hmac算法计算数据的签名，将签名附在数据后，用&ldquo;.&rdquo;分割</li>\r\n</ol>\r\n\r\n<p>第4步就解决了用户篡改session的问题，因为在不知道secret_key的情况下，是无法伪造签名的。</p>\r\n\r\n<p>最后，我们在cookie中就能看到设置好的session了：</p>\r\n\r\n<figure class=\"easyimage easyimage-full\"><img alt=\"\" src=\"blob:http://localhost:8080/b9176fda-9fc1-413e-9e78-4ba3ed182755\" width=\"552\" />\r\n<figcaption></figcaption>\r\n</figure>\r\n\r\n<p>注意到，在第4步中，flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的，这就可能造成一些安全问题。</p>\r\n\r\n<h2>0x03 flask客户端session导致敏感信息泄露</h2>\r\n\r\n<p>我曾遇到过一个案例，目标是flask开发的一个简历管理系统，在测试其找回密码功能的时候，我收到了服务端设置的session。</p>\r\n\r\n<p>我在0x02中说过，flask是一个客户端session，所以看目标为flask的站点的时候，我习惯性地去解密其session。编写如下代码解密session：</p>\r\n\r\n<pre>\r\n<code>#!/usr/bin/env python3\r\nimport sys\r\nimport zlib\r\nfrom base64 import b64decode\r\nfrom flask.sessions import session_json_serializer\r\nfrom itsdangerous import base64_decode\r\n\r\ndef decryption(payload):\r\n    payload, sig = payload.rsplit(b&#39;.&#39;, 1)\r\n    payload, timestamp = payload.rsplit(b&#39;.&#39;, 1)\r\n\r\n    decompress = False\r\n    if payload.startswith(b&#39;.&#39;):\r\n        payload = payload[1:]\r\n        decompress = True\r\n\r\n    try:\r\n        payload = base64_decode(payload)\r\n    except Exception as e:\r\n        raise Exception(&#39;Could not base64 decode the payload because of &#39;\r\n                         &#39;an exception&#39;)\r\n\r\n    if decompress:\r\n        try:\r\n            payload = zlib.decompress(payload)\r\n        except Exception as e:\r\n            raise Exception(&#39;Could not zlib decompress the payload before &#39;\r\n                             &#39;decoding the payload&#39;)\r\n\r\n    return session_json_serializer.loads(payload)\r\n\r\nif __name__ == &#39;__main__&#39;:\r\n    print(decryption(sys.argv[1].encode()))\r\n</code></pre>\r\n\r\n<p>例如，我解密0x02中演示的session：</p>\r\n\r\n<figure class=\"easyimage easyimage-full\"><img alt=\"\" src=\"blob:http://localhost:8080/9567ed89-57bd-4d4f-8f6c-3a43b514200b\" width=\"720\" />\r\n<figcaption></figcaption>\r\n</figure>\r\n\r\n<p>通过解密目标站点的session，我发现其设置了一个名为token、值是一串md5的键。猜测其为找回密码的认证，将其替换到找回密码链接的token中，果然能够进入修改密码页面。通过这个过程，我就能修改任意用户密码了。</p>\r\n\r\n<p>这是一个比较典型的安全问题，目标网站通过session来储存随机token并认证用户是否真的在邮箱收到了这个token。但因为flask的session是存储在cookie中且仅签名而未加密，所以我们就可以直接读取这个token了。</p>\r\n\r\n<h2>0x04 flask验证码绕过漏洞</h2>\r\n\r\n<p>这是客户端session的另一个常见漏洞场景。</p>\r\n\r\n<p>我们用一个实际例子认识这一点：<a href=\"https://link.zhihu.com/?target=https%3A//github.com/shonenada/flask-captcha\" target=\"_blank\">https://github.com/shonenada/flask-captcha</a> 。这是一个为flask提供验证码的项目，我们看到其中的view文件：</p>\r\n\r\n<pre>\r\n<code>import random\r\ntry:\r\n    from cStringIO import StringIO\r\nexcept ImportError:\r\n    from io import BytesIO as StringIO\r\n\r\nfrom flask import Blueprint, make_response, current_app, session\r\nfrom wheezy.captcha.image import captcha\r\nfrom wheezy.captcha.image import background\r\nfrom wheezy.captcha.image import curve\r\nfrom wheezy.captcha.image import noise\r\nfrom wheezy.captcha.image import smooth\r\nfrom wheezy.captcha.image import text\r\nfrom wheezy.captcha.image import offset\r\nfrom wheezy.captcha.image import rotate\r\nfrom wheezy.captcha.image import warp\r\n\r\n\r\ncaptcha_bp = Blueprint(&#39;captcha&#39;, __name__)\r\n\r\n\r\ndef sample_chars():\r\n    characters = current_app.config[&#39;CAPTCHA_CHARACTERS&#39;]\r\n    char_length = current_app.config[&#39;CAPTCHA_CHARS_LENGTH&#39;]\r\n    captcha_code = random.sample(characters, char_length)\r\n    return captcha_code\r\n\r\n@captcha_bp.route(&#39;/captcha&#39;, endpoint=&quot;captcha&quot;)\r\ndef captcha_view():\r\n    out = StringIO()\r\n    captcha_image = captcha(drawings=[\r\n        background(),\r\n        text(fonts=current_app.config[&#39;CAPTCHA_FONTS&#39;],\r\n             drawings=[warp(), rotate(), offset()]),\r\n        curve(),\r\n        noise(),\r\n        smooth(),\r\n    ])\r\n    captcha_code = &#39;&#39;.join(sample_chars())\r\n    imgfile = captcha_image(captcha_code)\r\n    session[&#39;captcha&#39;] = captcha_code\r\n    imgfile.save(out, &#39;PNG&#39;)\r\n    out.seek(0)\r\n    response = make_response(out.read())\r\n    response.content_type = &#39;image/png&#39;\r\n    return response\r\n</code></pre>\r\n\r\n<p>可见，其生成验证码后，就存储在session中了：<code>session[&#39;captcha&#39;] = captcha_code</code>。</p>\r\n\r\n<p>我们用浏览器访问<code>/captcha</code>，即可得到生成好的验证码图片，此时复制保存在cookie中的session值，用0x03中提供的脚本进行解码：</p>\r\n\r\n<figure class=\"easyimage easyimage-full\"><img alt=\"\" src=\"blob:http://localhost:8080/4e9110e4-4df6-4175-ba71-9e6dcbf61d7e\" width=\"720\" />\r\n<figcaption></figcaption>\r\n</figure>\r\n\r\n<p>可见，我成功获取了验证码的值，进而可以绕过验证码的判断。</p>\r\n\r\n<p>这也是客户端session的一种错误使用方法。</p>\r\n\r\n<h2>0x05 CodeIgniter 2.1.4 session伪造及对象注入漏洞</h2>\r\n\r\n<p>Codeigniter 2的session也储存在session中，默认名为<code>ci_session</code>，默认值如下：</p>\r\n\r\n<figure class=\"easyimage easyimage-full\"><img alt=\"\" src=\"blob:http://localhost:8080/9109c4c3-8fd4-4fee-8ad3-377ed7de3744\" width=\"720\" />\r\n<figcaption></figcaption>\r\n</figure>\r\n\r\n<p>可见，session数据被用PHP自带的serialize函数进行序列化，并签名后作为<code>ci_session</code>的值。原理上和flask如出一辙，我就不重述了。但好在codeigniter2支持对session进行加密，只需在配置文件中设置<code>$config[&#39;sess_encrypt_cookie&#39;] = TRUE;</code>即可。</p>\r\n\r\n<p>在CI2.1.4及以前的版本中，存在一个弱加密漏洞（ <a href=\"https://link.zhihu.com/?target=https%3A//www.dionach.com/blog/codeigniter-session-decoding-vulnerability\" target=\"_blank\">https://www.dionach.com/blog/codeigniter-session-decoding-vulnerability</a> ），如果目标环境中没有安装Mcrypt扩展，则CI会使用一个相对比较弱的加密方式来处理session:</p>\r\n\r\n<pre>\r\n<code>function _xor_encode($string, $key)\r\n{\r\n $rand = &#39;&#39;;\r\n while (strlen($rand) &lt; 32)\r\n {\r\n  $rand .= mt_rand(0, mt_getrandmax());\r\n }\r\n $rand = $this-&gt;hash($rand);\r\n $enc = &#39;&#39;;\r\n for ($i = 0; $i &lt; strlen($string); $i++)\r\n {\r\n  $enc .= substr($rand, ($i % strlen($rand)), 1).(substr($rand, ($i % strlen($rand)), 1) ^ substr($string, $i, 1));\r\n }\r\n return $this-&gt;_xor_merge($enc, $key);\r\n}\r\n\r\nfunction _xor_merge($string, $key)\r\n{\r\n $hash = $this-&gt;hash($key);\r\n $str = &#39;&#39;;\r\n for ($i = 0; $i &lt; strlen($string); $i++)\r\n {\r\n  $str .= substr($string, $i, 1) ^ substr($hash, ($i % strlen($hash)), 1);\r\n }\r\n return $str;\r\n}\r\n</code></pre>\r\n\r\n<p>其中用到了<code>mt_rand</code>、异或等存在大量缺陷的方法。我们通过几个简单的脚本（ <a href=\"https://link.zhihu.com/?target=https%3A//github.com/Dionach/CodeIgniterXor\" target=\"_blank\">https://github.com/Dionach/CodeIgniterXor</a> ），即可在4秒到4分钟的时间，破解CI2的密钥。</p>\r\n\r\n<p>获取到了密钥，我们即可篡改任意session，并自己签名及加密，最后伪造任意用户，注入任意对象，甚至通过反序列化操作造成更大的危害。</p>\r\n\r\n<h2>0x06 总结</h2>\r\n\r\n<p>我以三个案例来说明了客户端session的安全问题。</p>\r\n\r\n<p>上述三个问题，如果session是储存在服务器文件或数据库中，则不会出现。当然，考虑到flask和ci都是非常轻量的web框架，很可能运行在无法操作文件系统或没有数据库的服务器上，所以客户端session是无法避免的。</p>\r\n\r\n<p>除此之外，我还能想到其他客户端session可能存在的安全隐患：</p>\r\n\r\n<ol>\r\n	<li>签名使用hash函数而非hmac函数，导致利用hash长度扩展攻击来伪造session</li>\r\n	<li>任意文件读取导致密钥泄露，进一步造成身份伪造漏洞或反序列化漏洞（ <a href=\"https://link.zhihu.com/?target=http%3A//www.loner.fm/drops/%23%21/drops/227.Codeigniter%2520%25E5%2588%25A9%25E7%2594%25A8%25E5%258A%25A0%25E5%25AF%2586Key%25EF%25BC%2588%25E5%25AF%2586%25E9%2592%25A5%25EF%25BC%2589%25E7%259A%2584%25E5%25AF%25B9%25E8%25B1%25A1%25E6%25B3%25A8%25E5%2585%25A5%25E6%25BC%258F%25E6%25B4%259E\" target=\"_blank\">http://www.loner.fm/drops/#!/drops/227.Codeigniter%20%E5%88%A9%E7%94%A8%E5%8A%A0%E5%AF%86Key%EF%BC%88%E5%AF%86%E9%92%A5%EF%BC%89%E7%9A%84%E5%AF%B9%E8%B1%A1%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E</a> ）</li>\r\n	<li>如果客户端session仅加密未签名，利用CBC字节翻转攻击，我们可以修改加密session中某部分数据，来达到身份伪造的目的</li>\r\n</ol>\r\n\r\n<p>上面说的几点，各位CTF出题人可以拿去做文章啦~嘿嘿。</p>\r\n\r\n<p>相对的，作为一个开发者，如果我们使用的web框架或web语言的session是存储在客户端中，那就必须牢记下面几点：</p>\r\n\r\n<ol>\r\n	<li>没有加密时，用户可以看到完整的session对象</li>\r\n	<li>加密/签名不完善或密钥泄露的情况下，用户可以修改任意session</li>\r\n	<li>使用强健的加密及签名算法，而不是自己造（反例discuz）</li>\r\n</ol>\r\n', '2020-10-02');

-- ----------------------------
-- Table structure for t_permission
-- ----------------------------
DROP TABLE IF EXISTS `t_permission`;
CREATE TABLE `t_permission`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `permissionName` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `roleId` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `roleId`(`roleId`) USING BTREE,
  CONSTRAINT `t_permission_ibfk_1` FOREIGN KEY (`roleId`) REFERENCES `t_role` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of t_permission
-- ----------------------------
INSERT INTO `t_permission` VALUES (1, 'admin:*', 1);
INSERT INTO `t_permission` VALUES (2, 'user:*', 2);

-- ----------------------------
-- Table structure for t_role
-- ----------------------------
DROP TABLE IF EXISTS `t_role`;
CREATE TABLE `t_role`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `roleName` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of t_role
-- ----------------------------
INSERT INTO `t_role` VALUES (1, 'admin');
INSERT INTO `t_role` VALUES (2, 'user');

-- ----------------------------
-- Table structure for t_source
-- ----------------------------
DROP TABLE IF EXISTS `t_source`;
CREATE TABLE `t_source`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filename` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `pubtime` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;


-- ----------------------------
-- Table structure for t_topic
-- ----------------------------
DROP TABLE IF EXISTS `t_topic`;
CREATE TABLE `t_topic`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `pubtime` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `detail` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `edituser` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `state` int(11) NULL DEFAULT 1,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of t_topic
-- ----------------------------
INSERT INTO `t_topic` VALUES (1, 'java好好学啊', '2020-10-01', '&nbsp;哈哈', 'user2', 1);

-- ----------------------------
-- Table structure for t_user
-- ----------------------------
DROP TABLE IF EXISTS `t_user`;
CREATE TABLE `t_user`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `password` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `email` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `state` int(11) NULL DEFAULT 1,
  `roleId` int(11) NULL DEFAULT 2,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `roleId`(`roleId`) USING BTREE,
  INDEX `username`(`username`) USING BTREE,
  CONSTRAINT `t_user_ibfk_1` FOREIGN KEY (`roleId`) REFERENCES `t_role` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of t_user
-- ----------------------------
INSERT INTO `t_user` VALUES (1, 'admin', '533acafff35d56aa156ec9ba9b500b40', '123@qq.com', 1, 1);
INSERT INTO `t_user` VALUES (2, 'user', '8c4fb7bf681156b52fea93442c7dffc9', 'test@qq.com', 1, 2);
INSERT INTO `t_user` VALUES (3, 'firenay', '8c4fb7bf681156b52fea93442c7dffc9', 'abc@qq.com', 1, 2);

-- ----------------------------
-- Table structure for t_video
-- ----------------------------
DROP TABLE IF EXISTS `t_video`;
CREATE TABLE `t_video`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `titleOrig` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `titleAlter` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `size` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `type` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `path` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `uploadTime` datetime(0) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
