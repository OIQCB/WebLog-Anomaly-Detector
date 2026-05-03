"""
日志解析模块
功能：解析Apache/Nginx混合格式的Web访问日志，提取关键字段
作者：毕业设计 - Web日志异常检测系统
"""

import re
import pandas as pd


def parse_log_file(filepath):
    """
    解析Web访问日志文件，提取每条日志的关键字段。

    参数:
        filepath (str): 日志文件的路径

    返回:
        pandas.DataFrame: 包含 ip, timestamp, method, url, status, size, user_agent 列的数据框

    日志格式示例:
        192.168.1.10 - - [20/May/2025:10:15:32 +0800] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"
    """
    # 定义正则表达式，匹配Apache/Nginx通用日志格式
    # 各捕获组依次为：IP地址、时间戳、请求方法、URL路径、协议版本、状态码、响应大小、来源页面、用户代理
    log_pattern = re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'  # 匹配IP地址，如 192.168.1.10
        r'\s+-\s+\S+\s+'                       # 匹配中间的 "- - " 或 "- user " 部分
        r'\[(?P<timestamp>[^\]]+)\]\s+'        # 匹配方括号中的时间戳
        r'"(?P<method>\w+)\s+'                 # 匹配请求方法（GET/POST等）
        r'(?P<url>.+?)\s+HTTP/\S+"\s+'         # 匹配请求URL和协议版本（URL可能含空格，用.+?非贪婪匹配）
        r'(?P<status>\d{3})\s+'                # 匹配HTTP状态码
        r'(?P<size>\d+|-)\s+'                  # 匹配响应大小（可能是数字或"-"）
        r'"(?P<referer>[^"]*)"\s+'             # 匹配Referer来源页面
        r'"(?P<user_agent>[^"]*)"'             # 匹配User-Agent用户代理字符串
    )

    # 用于存储解析结果的列表
    records = []

    # 打开日志文件逐行读取
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # 用正则匹配当前行
            match = log_pattern.match(line.strip())
            if match:
                # 匹配成功，提取各字段
                record = {
                    'ip': match.group('ip'),              # 客户端IP地址
                    'timestamp': match.group('timestamp'), # 请求时间
                    'method': match.group('method'),       # 请求方法
                    'url': match.group('url'),             # 请求URL
                    'status': int(match.group('status')),  # 状态码转为整数
                    'size': int(match.group('size')) if match.group('size') != '-' else 0,  # 响应大小，"-"转为0
                    'user_agent': match.group('user_agent') # 浏览器标识
                }
                records.append(record)

    # 将解析结果转换为DataFrame
    df = pd.DataFrame(records)

    # 如果解析结果为空，返回一个带有正确列名的空DataFrame
    if df.empty:
        df = pd.DataFrame(columns=['ip', 'timestamp', 'method', 'url', 'status', 'size', 'user_agent'])

    # 对缺失值做容错处理：字符串列填充空字符串，数值列填充0
    df['ip'] = df['ip'].fillna('')
    df['timestamp'] = df['timestamp'].fillna('')
    df['method'] = df['method'].fillna('GET')
    df['url'] = df['url'].fillna('/')
    df['status'] = df['status'].fillna(0)
    df['size'] = df['size'].fillna(0)
    df['user_agent'] = df['user_agent'].fillna('')

    return df


# 如果直接运行此模块，执行简单测试
if __name__ == '__main__':
    # 测试解析功能
    test_line = '192.168.1.10 - - [20/May/2025:10:15:32 +0800] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"'
    print("测试日志行：", test_line)
    print("请通过 app.py 运行完整流程")
