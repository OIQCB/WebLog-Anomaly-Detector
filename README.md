# Web日志异常检测与可视化系统

基于规则引擎 + IsolationForest机器学习的Web攻击检测系统，支持SQL注入、XSS攻击、路径遍历等异常行为的自动识别与可视化展示。

---

## 一、环境要求

- Python 3.9 或更高版本
- pip 包管理工具

## 二、安装依赖

```bash
cd C:\Users\l2386\Desktop\web\weblog_anomaly_detector
pip install -r requirements.txt
```

如果下载速度慢，可以使用国内镜像源：

```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## 三、启动项目

```bash
python app.py
```

首次启动时系统会自动执行以下流程：

1. 生成模拟日志文件 `sample_web.log`（500条）
2. 解析日志，提取URL特征
3. 运行规则 + IsolationForest 异常检测
4. 将分析结果保存到 `result.csv`
5. 启动Web服务器

看到以下提示说明启动成功：

```
* Running on http://127.0.0.1:5000
```

打开浏览器访问：**http://127.0.0.1:5000**

## 四、仪表盘功能说明

页面包含以下内容，数据每30秒自动刷新：

### 1. 统计卡片（页面顶部）

| 指标 | 说明 |
|------|------|
| 总请求数 | 日志中的全部请求记录数 |
| 异常请求数 | 被检测为异常的请求数 |
| 异常率 | 异常请求占总请求的百分比 |
| 攻击类型数 | 检测到的不同攻击种类数量 |

### 2. 24小时攻击趋势（折线图）

- 横轴为 0-23 小时，纵轴为异常请求数
- 可观察攻击在一天中的分布规律

### 3. 攻击类型分布（饼图）

- 显示 SQL注入、XSS攻击、路径遍历、未知异常 的占比

### 4. Top10 IP排行（横向柱状图）

- 显示发出异常请求最多的前10个IP地址

### 5. 最近异常记录（表格）

- 展示最近20条异常请求的详细信息
- 包含：时间、IP地址、请求URL、攻击类型、异常得分

## 五、项目文件说明

```
weblog_anomaly_detector/
├── app.py                    # 主应用（路由、API、启动入口）
├── log_parser.py             # 日志解析（正则提取各字段）
├── feature_extraction.py     # 特征提取（URL长度、特殊字符、SQL/XSS标记等）
├── anomaly_detection.py      # 异常检测（规则 + IsolationForest机器学习）
├── sample_log_generator.py   # 模拟日志生成（70%正常 + 30%攻击）
├── requirements.txt          # Python依赖包列表
├── sample_web.log            # 生成的日志文件（首次运行后出现）
├── result.csv                # 分析结果（首次运行后出现）
├── 运行说明.txt               # 运行说明（纯文本版）
├── README.md                 # 本文件
└── templates/
    └── dashboard.html        # 仪表盘前端页面
```

## 六、API接口说明

以下接口均返回JSON格式数据，可供前端或外部工具调用：

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 仪表盘页面 |
| `/api/stats` | GET | 总体统计数据（总请求、异常数、异常率、攻击类型数） |
| `/api/anomaly_timeline` | GET | 24小时异常趋势（折线图数据） |
| `/api/anomaly_type_dist` | GET | 攻击类型分布（饼图数据） |
| `/api/top_ip` | GET | Top10异常IP排行（柱状图数据） |
| `/api/recent_anomalies` | GET | 最近20条异常记录（表格数据） |

### 接口返回示例

**GET /api/stats**

```json
{
  "total_requests": 500,
  "anomaly_count": 150,
  "anomaly_rate": "30.0%",
  "attack_types": 4
}
```

**GET /api/anomaly_type_dist**

```json
[
  {"name": "XSS攻击", "value": 50},
  {"name": "SQL注入", "value": 50},
  {"name": "路径遍历", "value": 27},
  {"name": "未知异常", "value": 23}
]
```

## 七、重新生成数据

如果想重新生成日志和分析结果，删除以下两个文件后重新运行即可：

```bash
del sample_web.log result.csv
python app.py
```

## 八、停止服务

在运行 `app.py` 的终端窗口按 `Ctrl + C` 即可停止服务器。

## 九、常见问题

### Q: pip install 报错或超时？

使用国内镜像源：

```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: 端口5000被占用？

修改 `app.py` 最后一行的 `port=5000` 改为其他端口，如 `port=8080`

### Q: 页面显示但图表为空？

检查浏览器控制台（F12）是否有网络错误，确认 `result.csv` 存在

### Q: 想用自己的真实日志测试？

将真实日志命名为 `sample_web.log` 放到项目目录下，删除 `result.csv` 后重启。日志需为 Apache/Nginx 通用格式（Combined Log Format）：

```
192.168.1.10 - - [20/May/2025:10:15:32 +0800] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"
```

---

## 十、技术栈

| 类别 | 技术 |
|------|------|
| 后端语言 | Python 3.9+ |
| Web框架 | Flask |
| 数据处理 | pandas, re, urllib.parse |
| 机器学习 | scikit-learn（IsolationForest） |
| 前端框架 | Bootstrap 5 |
| 可视化 | ECharts |
