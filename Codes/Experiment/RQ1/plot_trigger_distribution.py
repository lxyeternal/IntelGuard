"""Plot the trigger distribution of PyPI and npm snippets."""
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]

plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

pypi_triggers = {
    'installation': 635,
    'runtime': 518,
    'import-time': 381,
    'build-time': 10
}

npm_triggers = {
    'runtime': 466,
    'postinstall': 351,
    'import-time': 213,
    'preinstall': 194,
    'installation': 94
}

all_triggers = sorted(set(list(pypi_triggers.keys()) + list(npm_triggers.keys())))

pypi_values = [pypi_triggers.get(t, 0) for t in all_triggers]
npm_values = [npm_triggers.get(t, 0) for t in all_triggers]

colors = {
    'PyPI': '#1f77b4',
    'NPM': '#ff7f0e'
}

fig, ax = plt.subplots(figsize=(10, 5))
fig.patch.set_facecolor('white')
ax.set_facecolor('white')

x = np.arange(len(all_triggers))
width = 0.35

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

def autolabel(bars):
    """Write the value above each bar."""
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(f'{int(height)}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=9, fontweight='bold')

autolabel(bars1)
autolabel(bars2)

ax.set_ylabel('Number of Occurrences', fontsize=14, fontweight='bold', labelpad=8)
ax.set_xlabel('Trigger Type', fontsize=14, fontweight='bold', labelpad=8)
ax.set_title('Trigger Distribution Comparison: PyPI vs NPM Ecosystems', 
             fontsize=16, fontweight='bold', pad=12)
ax.set_xticks(x)
ax.set_xticklabels(all_triggers, fontsize=12, rotation=45, ha='right')

ax.legend(fontsize=12, loc='upper right', frameon=True, 
         edgecolor='#333', fancybox=False, shadow=False,
         framealpha=0.85, borderpad=0.6)

ax.tick_params(axis='both', labelsize=11, width=1.2, length=5)

ax.yaxis.grid(True, linestyle='--', linewidth=0.6, alpha=0.4, zorder=0)
ax.set_axisbelow(True)

ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_linewidth(1.2)
ax.spines['bottom'].set_linewidth(1.2)
ax.spines['left'].set_color('black')
ax.spines['bottom'].set_color('black')

plt.tight_layout()
plt.savefig(f'{PROJECT_ROOT}/Codes/Experiment/RQ1/trigger_distribution_comparison.png', 
            dpi=600, bbox_inches='tight', 
            facecolor='white', edgecolor='none')
plt.close()

print("\n✓ Trigger distribution figure generated")
print("Output: trigger_distribution_comparison.png")
print("\nStatistics:")
print(f"PyPI triggers: {sum(pypi_values)}")
print(f"NPM triggers: {sum(npm_values)}")
print(f"\nTop 3 triggers (PyPI):")
for i, trigger in enumerate(sorted(pypi_triggers.items(), key=lambda x: x[1], reverse=True)[:3], 1):
    print(f"  {i}. {trigger[0]}: {trigger[1]}")
print(f"\nTop 3 triggers (NPM):")
for i, trigger in enumerate(sorted(npm_triggers.items(), key=lambda x: x[1], reverse=True)[:3], 1):
    print(f"  {i}. {trigger[0]}: {trigger[1]}")

