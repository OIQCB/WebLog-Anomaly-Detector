"""
异常检测模块
功能：结合规则检测和IsolationForest机器学习模型，对Web请求进行异常判定
作者：毕业设计 - Web日志异常检测系统
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def detect_anomalies(df):
    """
    对已包含解析字段和URL特征的DataFrame进行异常检测。

    检测策略：
        1. 规则检测：基于明确的攻击特征快速标记
        2. ML检测：使用IsolationForest对数值特征建模，发现统计异常
        3. 综合判定：规则优先，ML辅助，输出最终结果

    参数:
        df (pandas.DataFrame): 必须包含以下列：
            - url: 原始请求URL
            - url_length, special_char_ratio, has_sql_keywords,
              has_xss_pattern, path_depth, num_query_params

    返回:
        pandas.DataFrame: 新增 is_anomaly, anomaly_type, anomaly_score 三列
    """
    # 创建副本，避免修改原始数据
    df = df.copy()

    # ============================
    # 第一步：规则检测
    # ============================
    # 初始化规则标记列，默认全部为False（正常）
    df['rule_flag'] = False

    # 规则1：检测SQL注入特征
    # has_sql_keywords 为1表示URL中包含SQL关键词
    df.loc[df['has_sql_keywords'] == 1, 'rule_flag'] = True

    # 规则2：检测XSS攻击特征
    # has_xss_pattern 为1表示URL中包含XSS攻击模式
    df.loc[df['has_xss_pattern'] == 1, 'rule_flag'] = True

    # 规则3：检测路径遍历攻击
    # 检查URL中是否包含 ../ 或其URL编码形式 %2e%2e/
    df.loc[df['url'].str.contains(r'\.\./|%2e%2e|%2E%2E', case=False, na=False), 'rule_flag'] = True

    # ============================
    # 第二步：IsolationForest机器学习检测
    # ============================
    # 选择用于机器学习的数值特征列
    ml_features = ['url_length', 'special_char_ratio', 'path_depth', 'num_query_params']

    # 提取特征矩阵
    X = df[ml_features].values

    # 数据标准化：将各特征缩放到均值为0、方差为1的分布
    # 这样不同量纲的特征可以在同一尺度上比较
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 创建IsolationForest模型
    # contamination=0.1 表示预估数据集中约10%为异常（与30%攻击样本部分重叠）
    # random_state=42 保证结果可复现
    # n_estimators=100 使用100棵决策树
    iso_forest = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100
    )

    # 训练模型并预测（-1为异常，1为正常）
    predictions = iso_forest.fit_predict(X_scaled)

    # 获取异常得分（越低越异常）
    # decision_function返回的分数越小，表示越偏离正常分布
    raw_scores = iso_forest.decision_function(X_scaled)

    # 将原始得分归一化到0-1范围，并反转（使得越大越异常）
    # 公式：(最大值 - 当前值) / (最大值 - 最小值)
    min_score = raw_scores.min()
    max_score = raw_scores.max()
    if max_score - min_score > 0:
        df['anomaly_score'] = (max_score - raw_scores) / (max_score - min_score)
    else:
        df['anomaly_score'] = 0  # 所有得分相同时，异常得分为0

    # ============================
    # 第三步：综合判定
    # ============================
    # 初始化最终异常标记和异常类型
    df['is_anomaly'] = 0       # 0=正常，1=异常
    df['anomaly_type'] = '正常'  # 默认类型为"正常"

    # 条件1：规则检测命中，或者ML异常得分超过阈值0.6
    # 满足任一条件即判定为异常
    anomaly_mask = (df['rule_flag'] == True) | (df['anomaly_score'] > 0.6)
    df.loc[anomaly_mask, 'is_anomaly'] = 1

    # ============================
    # 第四步：分类异常类型
    # ============================
    # 按优先级分类：SQL注入 > XSS > 路径遍历 > 未知异常

    # SQL注入：URL中包含SQL关键词
    sql_mask = (df['is_anomaly'] == 1) & (df['has_sql_keywords'] == 1)
    df.loc[sql_mask, 'anomaly_type'] = 'SQL注入'

    # XSS攻击：URL中包含XSS模式
    xss_mask = (df['is_anomaly'] == 1) & (df['has_xss_pattern'] == 1)
    df.loc[xss_mask, 'anomaly_type'] = 'XSS攻击'

    # 路径遍历：URL中包含 ../ 或编码形式
    traversal_mask = (df['is_anomaly'] == 1) & (
        df['url'].str.contains(r'\.\./|%2e%2e|%2E%2E', case=False, na=False)
    )
    df.loc[traversal_mask, 'anomaly_type'] = '路径遍历'

    # 未知异常：被标记为异常但不属于以上三类
    # 注意：一个请求可能同时命中多种攻击类型，这里取最后赋值的结果
    unknown_mask = (df['is_anomaly'] == 1) & (df['anomaly_type'] == '正常')
    df.loc[unknown_mask, 'anomaly_type'] = '未知异常'

    # 删除临时的规则标记列，不暴露给前端
    df.drop(columns=['rule_flag'], inplace=True)

    return df


# 直接运行时的测试说明
if __name__ == '__main__':
    print("异常检测模块")
    print("请通过 app.py 运行完整流程，或导入此模块调用 detect_anomalies(df)")
