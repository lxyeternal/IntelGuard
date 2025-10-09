import matplotlib.pyplot as plt
import numpy as np

# 学术论文风格设置
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

# 触发器数据 (来自rq1_deep_insights_report.txt)
# PyPI Top触发器 (移除了NPM专属的postinstall和preinstall)
pypi_triggers = {
    'installation': 635,
    'runtime': 518,
    'import-time': 381,
    'build-time': 10
}

# NPM Top触发器 (移除了startup)
npm_triggers = {
    'runtime': 466,
    'postinstall': 351,
    'import-time': 213,
    'preinstall': 194,
    'installation': 94
}

# 获取所有触发器类型的并集
all_triggers = sorted(set(list(pypi_triggers.keys()) + list(npm_triggers.keys())))

# 准备数据
pypi_values = [pypi_triggers.get(t, 0) for t in all_triggers]
npm_values = [npm_triggers.get(t, 0) for t in all_triggers]

# 学术风格配色
colors = {
    'PyPI': '#1f77b4',  # 专业蓝
    'NPM': '#ff7f0e'     # 活力橙
}

# 创建图表
fig, ax = plt.subplots(figsize=(10, 5))
fig.patch.set_facecolor('white')
ax.set_facecolor('white')

x = np.arange(len(all_triggers))
width = 0.35

# 绘制条形图
bars1 = ax.bar(x - width/2, pypi_values, width, 
               label='PyPI',
               color=colors['PyPI'],
               alpha=0.85,
               edgecolor='#2c3e50',
               linewidth=0.9,
               zorder=3)

bars2 = ax.bar(x + width/2, npm_values, width,
               label='NPM',
               color=colors['NPM'],
               alpha=0.85,
               edgecolor='#2c3e50',
               linewidth=0.9,
               zorder=3)

# 在条形上添加数值标签
def autolabel(bars):
    """在条形图上添加数值标签"""
    for bar in bars:
        height = bar.get_height()
        if height > 0:  # 只为非零值添加标签
            ax.annotate(f'{int(height)}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),  # 3点偏移
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=9, fontweight='bold')

autolabel(bars1)
autolabel(bars2)

# 标题和标签
ax.set_ylabel('Number of Occurrences', fontsize=14, fontweight='bold', labelpad=8)
ax.set_xlabel('Trigger Type', fontsize=14, fontweight='bold', labelpad=8)
ax.set_title('Trigger Distribution Comparison: PyPI vs NPM Ecosystems', 
             fontsize=16, fontweight='bold', pad=12)
ax.set_xticks(x)
ax.set_xticklabels(all_triggers, fontsize=12, rotation=45, ha='right')

# 图例
ax.legend(fontsize=12, loc='upper right', frameon=True, 
         edgecolor='#333', fancybox=False, shadow=False,
         framealpha=0.85, borderpad=0.6)

# Y轴刻度
ax.tick_params(axis='both', labelsize=11, width=1.2, length=5)

# 网格线
ax.yaxis.grid(True, linestyle='--', linewidth=0.6, alpha=0.4, zorder=0)
ax.set_axisbelow(True)

# 边框设置
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_linewidth(1.2)
ax.spines['bottom'].set_linewidth(1.2)
ax.spines['left'].set_color('black')
ax.spines['bottom'].set_color('black')

plt.tight_layout()
plt.savefig('/home2/wenbo/Documents/IntelliGraph/Codes/Experiment/RQ1/trigger_distribution_comparison.png', 
            dpi=600, bbox_inches='tight', 
            facecolor='white', edgecolor='none')
plt.close()

print("\n✓ 触发器分布对比图已生成！")
print("输出文件: trigger_distribution_comparison.png")
print("\n数据统计:")
print(f"PyPI总触发次数: {sum(pypi_values)}")
print(f"NPM总触发次数: {sum(npm_values)}")
print(f"\nTop 3 触发器 (PyPI):")
for i, trigger in enumerate(sorted(pypi_triggers.items(), key=lambda x: x[1], reverse=True)[:3], 1):
    print(f"  {i}. {trigger[0]}: {trigger[1]}")
print(f"\nTop 3 触发器 (NPM):")
for i, trigger in enumerate(sorted(npm_triggers.items(), key=lambda x: x[1], reverse=True)[:3], 1):
    print(f"  {i}. {trigger[0]}: {trigger[1]}")

