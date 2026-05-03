"""
URL特征提取模块
功能：从请求URL中提取用于异常检测的数值特征和规则标记
作者：毕业设计 - Web日志异常检测系统
"""

import re
from urllib.parse import unquote


def extract_url_features(url):
    """
    对单个URL提取多维特征，用于后续的异常检测。

    参数:
        url (str): 原始请求URL，如 /index.html?id=1

    返回:
        dict: 包含以下特征的字典
            - url_length: URL总长度
            - special_char_ratio: 特殊字符占比
            - has_sql_keywords: 是否包含SQL注入关键词（1或0）
            - has_xss_pattern: 是否包含XSS攻击模式（1或0）
            - path_depth: URL路径层级深度
            - num_query_params: 查询参数个数
    """
    # 先对URL做一次URL解码，绕过简单的编码绕过（如 %27 -> '）
    decoded_url = unquote(url)

    # === 1. URL总长度 ===
    # 攻击URL通常比正常URL长很多，因为包含payload
    url_length = len(decoded_url)

    # === 2. 特殊字符占比 ===
    # 统计 ? % & = ; / ' " < > 等特殊字符的数量
    special_chars = re.findall(r'[?%&=;/\'"<>#\-\+\*\(\)\{\}]', decoded_url)
    # 计算占比：特殊字符数 / URL总长度，避免除以零
    special_char_ratio = len(special_chars) / url_length if url_length > 0 else 0

    # === 3. SQL注入关键词检测 ===
    # 定义常见的SQL注入关键词和符号，忽略大小写
    sql_patterns = [
        r'\bselect\b',    # SELECT查询
        r'\bunion\b',     # UNION联合查询
        r'\binsert\b',    # INSERT插入
        r'\bdrop\b',      # DROP删除表
        r'\bdelete\b',    # DELETE删除数据
        r'\bupdate\b',    # UPDATE更新
        r'\bwhere\b',     # WHERE条件
        r'\bor\b',        # OR逻辑（常用于 '1'='1' 绕过）
        r'\band\b',       # AND逻辑
        r'--',            # SQL注释符
        r'/\*',           # SQL块注释开始
        r'\*/',           # SQL块注释结束
        r"'",             # 单引号（SQL注入常用）
        r';',             # 分号（多语句执行）
        r'\bchar\b',      # CHAR函数
        r'\bexec\b',      # EXEC执行
        r'\bconcat\b',    # CONCAT拼接
    ]
    # 用正则在解码后的URL中搜索，忽略大小写
    has_sql_keywords = 1 if any(
        re.search(pattern, decoded_url, re.IGNORECASE) for pattern in sql_patterns
    ) else 0

    # === 4. XSS攻击模式检测 ===
    # 定义常见的XSS攻击特征
    xss_patterns = [
        r'<script',           # script标签注入
        r'onerror\s*=',       # onerror事件处理器
        r'onload\s*=',        # onload事件处理器
        r'onclick\s*=',       # onclick事件处理器
        r'javascript\s*:',    # javascript伪协议
        r'alert\s*\(',        # alert弹窗函数
        r'document\.cookie',  # 读取Cookie
        r'<img\s',            # img标签注入
        r'<iframe',           # iframe标签注入
        r'<svg\s',            # svg标签注入
        r'expression\s*\(',   # CSS表达式
        r'eval\s*\(',         # eval函数
    ]
    # 检查URL中是否包含任何XSS模式
    has_xss_pattern = 1 if any(
        re.search(pattern, decoded_url, re.IGNORECASE) for pattern in xss_patterns
    ) else 0

    # === 5. 路径深度 ===
    # 统计URL中'/'的数量减1，用于判断路径层级
    # 例如 /images/logo.png 的深度为2
    # 先去掉查询参数部分，只计算路径
    path_part = decoded_url.split('?')[0]  # 取问号前的路径部分
    path_depth = path_part.count('/') - 1 if path_part.count('/') > 0 else 0
    # 深度不能为负数
    path_depth = max(path_depth, 0)

    # === 6. 查询参数个数 ===
    # 统计URL中'&'的数量加1（如果有'?'的话）
    if '?' in decoded_url:
        query_part = decoded_url.split('?', 1)[1]  # 取问号后的查询部分
        num_query_params = query_part.count('&') + 1  # 每个&分隔一个参数
    else:
        num_query_params = 0  # 没有问号就没有查询参数

    # 返回所有特征组成的字典
    return {
        'url_length': url_length,                # URL长度
        'special_char_ratio': special_char_ratio, # 特殊字符占比
        'has_sql_keywords': has_sql_keywords,     # SQL注入标记
        'has_xss_pattern': has_xss_pattern,       # XSS攻击标记
        'path_depth': path_depth,                 # 路径深度
        'num_query_params': num_query_params,     # 查询参数个数
    }


# 直接运行时的测试
if __name__ == '__main__':
    # 测试几个典型的URL
    test_urls = [
        '/index.html',                                      # 正常首页
        '/api/user?id=3',                                   # 正常API
        "/products.php?cat=1' UNION SELECT username,password FROM users--",  # SQL注入
        '/search?q=<script>alert(1)</script>',              # XSS攻击
        '/../../../etc/passwd',                             # 路径遍历
    ]
    for url in test_urls:
        features = extract_url_features(url)
        print(f"URL: {url}")
        print(f"  特征: {features}")
        print()
