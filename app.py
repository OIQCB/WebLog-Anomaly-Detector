"""
Flask主应用模块
功能：Web日志异常检测系统的主入口，包含所有路由和API接口
作者：毕业设计 - Web日志异常检测系统

启动方式：
    python app.py
    然后在浏览器访问 http://127.0.0.1:5000
"""

import os
import pandas as pd
from flask import Flask, render_template, jsonify

# 导入自定义模块
from log_parser import parse_log_file           # 日志解析
from feature_extraction import extract_url_features  # 特征提取
from anomaly_detection import detect_anomalies   # 异常检测
from sample_log_generator import generate_sample_log  # 日志生成

# 创建Flask应用实例
app = Flask(__name__)

# 定义文件路径常量
LOG_FILE = 'sample_web.log'      # 原始日志文件
RESULT_FILE = 'result.csv'       # 分析结果文件


def run_pipeline():
    """
    运行完整的日志分析流水线。

    流程：生成日志 -> 解析日志 -> 提取特征 -> 异常检测 -> 保存结果

    返回:
        pandas.DataFrame: 最终的分析结果DataFrame
    """
    print("=" * 50)
    print("开始运行日志分析流水线")
    print("=" * 50)

    # 第1步：生成模拟日志（如果日志文件不存在）
    if not os.path.exists(LOG_FILE):
        print("\n[步骤1/4] 生成模拟日志文件...")
        generate_sample_log(LOG_FILE)
    else:
        print(f"\n[步骤1/4] 日志文件 {LOG_FILE} 已存在，跳过生成")

    # 第2步：解析日志文件
    print("\n[步骤2/4] 解析日志文件...")
    df = parse_log_file(LOG_FILE)
    print(f"  成功解析 {len(df)} 条日志记录")

    # 第3步：提取URL特征
    print("\n[步骤3/4] 提取URL特征...")
    # 对每条记录的URL提取特征，生成新的特征列
    features_list = df['url'].apply(extract_url_features).tolist()
    # 将特征字典列表转换为DataFrame
    features_df = pd.DataFrame(features_list)
    # 将特征列合并到原始DataFrame中
    df = pd.concat([df, features_df], axis=1)
    print(f"  已提取 {len(features_df.columns)} 个特征维度")

    # 第4步：异常检测
    print("\n[步骤4/4] 执行异常检测...")
    df = detect_anomalies(df)
    # 统计检测结果
    anomaly_count = df['is_anomaly'].sum()
    print(f"  检测到 {anomaly_count} 条异常请求")

    # 保存结果到CSV文件
    df.to_csv(RESULT_FILE, index=False, encoding='utf-8-sig')
    print(f"\n分析结果已保存到 {RESULT_FILE}")
    print("=" * 50)

    return df


def load_data():
    """
    加载分析结果数据。

    如果result.csv不存在，先运行分析流水线。
    如果已存在，直接从CSV读取。

    返回:
        pandas.DataFrame: 包含分析结果的DataFrame
    """
    if os.path.exists(RESULT_FILE):
        # 结果文件已存在，直接读取
        df = pd.read_csv(RESULT_FILE, encoding='utf-8-sig')
    else:
        # 结果文件不存在，运行完整流水线
        df = run_pipeline()
    return df


# ============================
# 页面路由
# ============================

@app.route('/')
def dashboard():
    """
    仪表盘页面路由。

    渲染主页面 dashboard.html，展示Web日志异常检测的可视化仪表盘。
    """
    return render_template('dashboard.html')


# ============================
# API接口
# ============================

@app.route('/api/anomaly_timeline')
def anomaly_timeline():
    """
    异常趋势时间线API。

    按小时统计异常请求数量，用于绘制折线图。

    返回:
        JSON: {
            "hours": ["00", "01", ..., "23"],  # 24小时标签
            "counts": [5, 3, ...]               # 每小时异常数
        }
    """
    df = load_data()

    # 只筛选异常记录
    anomalies = df[df['is_anomaly'] == 1].copy()

    if anomalies.empty:
        # 没有异常数据，返回全零
        return jsonify({
            'hours': [f'{h:02d}' for h in range(24)],
            'counts': [0] * 24
        })

    # 从时间戳中提取小时数
    # 时间戳格式：20/May/2025:10:15:32 +0800
    anomalies['hour'] = anomalies['timestamp'].str.extract(r':(\d{2}):')[0]

    # 按小时分组统计数量
    hour_counts = anomalies.groupby('hour').size()

    # 构建完整的24小时数据（缺失的小时补0）
    hours = [f'{h:02d}' for h in range(24)]
    counts = [int(hour_counts.get(h, 0)) for h in hours]

    return jsonify({'hours': hours, 'counts': counts})


@app.route('/api/anomaly_type_dist')
def anomaly_type_dist():
    """
    异常类型分布API。

    统计各攻击类型的数量，用于绘制饼图。

    返回:
        JSON: [{"name": "SQL注入", "value": 34}, ...]
    """
    df = load_data()

    # 只筛选异常记录
    anomalies = df[df['is_anomaly'] == 1]

    if anomalies.empty:
        return jsonify([])

    # 按异常类型分组统计
    type_counts = anomalies['anomaly_type'].value_counts()

    # 转换为ECharts饼图需要的格式
    result = [
        {'name': str(name), 'value': int(count)}
        for name, count in type_counts.items()
    ]

    return jsonify(result)


@app.route('/api/top_ip')
def top_ip():
    """
    Top10异常IP排行API。

    统计发出异常请求最多的前10个IP地址，用于绘制柱状图。

    返回:
        JSON: [{"ip": "192.168.1.10", "count": 15}, ...]
    """
    df = load_data()

    # 只筛选异常记录
    anomalies = df[df['is_anomaly'] == 1]

    if anomalies.empty:
        return jsonify([])

    # 按IP分组统计，取前10名
    ip_counts = anomalies['ip'].value_counts().head(10)

    # 转换为JSON格式
    result = [
        {'ip': str(ip), 'count': int(count)}
        for ip, count in ip_counts.items()
    ]

    return jsonify(result)


@app.route('/api/recent_anomalies')
def recent_anomalies():
    """
    最近异常记录API。

    返回最近的20条异常请求记录，用于在表格中展示。

    返回:
        JSON: [{"timestamp": "...", "ip": "...", "url": "...", "anomaly_type": "..."}, ...]
    """
    df = load_data()

    # 只筛选异常记录，取最后20条（最近的）
    anomalies = df[df['is_anomaly'] == 1].tail(20)

    # 选择需要展示的列，并转换为字典列表
    result = anomalies[['timestamp', 'ip', 'url', 'anomaly_type', 'anomaly_score']].to_dict('records')

    # 反转顺序，最新的在前面
    result.reverse()

    # 格式化anomaly_score保留两位小数
    for record in result:
        if 'anomaly_score' in record:
            record['anomaly_score'] = round(float(record['anomaly_score']), 2)

    return jsonify(result)


@app.route('/api/stats')
def stats():
    """
    总体统计API。

    返回仪表盘顶部卡片需要的汇总数据。

    返回:
        JSON: {
            "total_requests": 500,
            "anomaly_count": 150,
            "anomaly_rate": "30.0%",
            "attack_types": 4
        }
    """
    df = load_data()

    total = len(df)                                      # 总请求数
    anomaly_count = int(df['is_anomaly'].sum())           # 异常请求数
    anomaly_rate = f"{(anomaly_count / total * 100):.1f}%" if total > 0 else "0%"  # 异常率
    # 攻击类型数（排除"正常"类型）
    attack_types = int(df[df['is_anomaly'] == 1]['anomaly_type'].nunique())

    return jsonify({
        'total_requests': total,
        'anomaly_count': anomaly_count,
        'anomaly_rate': anomaly_rate,
        'attack_types': attack_types
    })


# ============================
# 应用启动入口
# ============================

if __name__ == '__main__':
    # 启动时检查结果文件，不存在则运行分析流水线
    if not os.path.exists(RESULT_FILE):
        print("首次启动，正在运行分析流水线...\n")
        run_pipeline()
    else:
        print(f"检测到已有分析结果 {RESULT_FILE}，跳过流水线\n")

    # 启动Flask开发服务器
    # host='0.0.0.0' 允许外部访问
    # port=5000 监听5000端口
    # debug=True 开启调试模式（代码修改后自动重载）
    print("启动Web服务器...")
    print("请在浏览器中访问: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
