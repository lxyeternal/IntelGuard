"""Ablation figures per dataset."""
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']

pypi_malkg = [99.00, 99.49, 98.50, 98.99]
pypi_gpt4 = [96.30, 94.86, 97.90, 96.36]
pypi_gpt4mini = [96.99, 97.86, 96.10, 96.97]

pypi_obf_malkg = [96.50, 95.84, 97.31, 96.57]
pypi_obf_gpt4 = [68.64, 61.89, 98.75, 76.09]
pypi_obf_gpt4mini = [52.82, 63.56, 15.14, 24.45]

npm_malkg = [98.72, 99.80, 97.67, 98.72]
npm_gpt4mini = [96.70, 97.73, 95.74, 96.73]

colors = {
    'IntelGuard': '#1f77b4',
    'GPT-4.1': '#ff7f0e',
    'GPT-4.1-mini': '#2ca02c'
}

x = np.arange(len(metrics))
width = 0.25

def create_elegant_plot(data_dict, title, filename, ylim_range):
    """Draw one grouped bar chart."""
    fig, ax = plt.subplots(figsize=(5, 4))
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    if len(data_dict) == 3:
        positions = [x - width, x, x + width]
    else:
        positions = [x - width/2, x + width/2]
    
    bars_list = []
    for i, (label, values) in enumerate(data_dict.items()):
        bars = ax.bar(positions[i], values, width, 
                     label=label,
                     color=colors[label.split()[0]],
                     alpha=0.85,
                     edgecolor='#2c3e50',
                     linewidth=0.9,
                     zorder=3)
        bars_list.append(bars)
    
    ax.set_ylabel('Performance (%)', fontsize=16, fontweight='bold', labelpad=10)
    ax.set_title(title, fontsize=18, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=15, rotation=0)
    
    ax.legend(fontsize=13, loc='upper right', frameon=True, 
             edgecolor='#333', fancybox=False, shadow=False,
             framealpha=0.75, borderpad=0.6)
    
    ax.set_ylim(ylim_range)
    ax.tick_params(axis='both', labelsize=14, width=1.2, length=5)
    
    ax.yaxis.grid(True, linestyle='--', linewidth=0.6, alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.2)
    ax.spines['bottom'].set_linewidth(1.2)
    ax.spines['left'].set_color('black')
    ax.spines['bottom'].set_color('black')
    
    plt.tight_layout()
    plt.savefig(filename, dpi=600, bbox_inches='tight', 
               facecolor='white', edgecolor='none')
    plt.close()
    print(f"✓ Saved: {filename}")

print("\nGenerating figures...\n")

create_elegant_plot(
    {
        'IntelGuard (Ours)': pypi_malkg,
        'GPT-4.1': pypi_gpt4,
        'GPT-4.1-mini': pypi_gpt4mini
    },
    'PyPI Ecosystem',
    'pypi_normal.png',
    (92, 102)
)

create_elegant_plot(
    {
        'IntelGuard (Ours)': pypi_obf_malkg,
        'GPT-4.1': pypi_obf_gpt4,
        'GPT-4.1-mini': pypi_obf_gpt4mini
    },
    'PyPI Obfuscated Dataset',
    'pypi_obfuscated.png',
    (10, 105)
)

create_elegant_plot(
    {
        'IntelGuard (Ours)': npm_malkg,
        'GPT-4.1-mini': npm_gpt4mini
    },
    'NPM Ecosystem',
    'npm_ecosystem.png',
    (93, 102)
)

print("\n✓ All figures generated")
print("Output: pypi_normal.png, pypi_obfuscated.png, npm_ecosystem.png")
