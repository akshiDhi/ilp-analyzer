#!/usr/bin/env python3
"""
visualizer.py — ILP Analyzer Visualization Suite
=================================================
Generates visual outputs from ILP analyzer results:
  1. Dependency graph (NetworkX + Matplotlib)
  2. Gantt / parallel execution timeline
  3. ILP comparison bar chart
  4. Dependency type distribution pie chart
  5. Cycle histogram (parallelism over time)

Usage:
    python3 visualizer.py --metrics output/metrics.json \
                           --timeline output/timeline.csv \
                           --outdir output/

Authors: Akshita Dhiman (2024CSB1098), Saloni Mahajan (2024CSB1149)
"""

import argparse
import json
import csv
import os
import sys
from pathlib import Path

def check_imports():
    missing = []
    for pkg in ['matplotlib', 'networkx', 'numpy']:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[Visualizer] Installing missing packages: {missing}")
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing])

check_imports()

import matplotlib
matplotlib.use('Agg')   # Non-interactive backend (works in WSL without display)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.colors as mcolors
import networkx as nx
import numpy as np

# ============================================================
# CATEGORY COLORS
# ============================================================
CATEGORY_COLORS = {
    'ARITH':   '#3498DB',  # Blue
    'LOGIC':   '#2ECC71',  # Green
    'MOVE':    '#F1C40F',  # Yellow
    'BRANCH':  '#E74C3C',  # Red
    'FLOAT':   '#9B59B6',  # Purple
    'COMPARE': '#E67E22',  # Orange
    'OTHER':   '#95A5A6',  # Gray
}

# ============================================================
# LOAD DATA
# ============================================================

def load_metrics(path):
    if not os.path.exists(path):
        print(f"[Visualizer] metrics.json not found: {path}")
        return None
    with open(path) as f:
        return json.load(f)

def load_timeline(path, max_rows=10000):
    if not os.path.exists(path):
        print(f"[Visualizer] timeline.csv not found: {path}")
        return []
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append({
                'node_id':      int(row['node_id']),
                'dyn_id':       int(row['dyn_id']),
                'opcode':       row['opcode'],
                'category':     row['category'],
                'hw_start':     int(row['hw_start_cycle']),
                'hw_end':       int(row['hw_end_cycle']),
                'sw_start':     int(row['sw_start_cycle']),
                'sw_end':       int(row['sw_end_cycle']),
                'latency':      int(row['latency']),
            })
    return rows

# ============================================================
# CHART 1: ILP COMPARISON BAR CHART
# ============================================================

def plot_ilp_comparison(metrics, outdir):
    if not metrics:
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor('#1a1a2e')

    # Left: ILP values bar chart
    ax = axes[0]
    ax.set_facecolor('#16213e')

    labels = ['Theoretical\nILP', 'HW Reorder\n(OOO)', 'SW Reorder\n(Compiler)']
    values = [
        metrics.get('theoretical_ilp', 0),
        metrics.get('hw_reorder_ilp', 0),
        metrics.get('sw_reorder_ilp', 0),
    ]
    colors = ['#E74C3C', '#3498DB', '#2ECC71']
    bars = ax.bar(labels, values, color=colors, edgecolor='white', linewidth=0.5,
                  width=0.5, zorder=3)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                f'{val:.3f}', ha='center', va='bottom',
                color='white', fontsize=11, fontweight='bold')

    ax.set_title('ILP Comparison', color='white', fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel('Instructions per Cycle (IPC)', color='white', fontsize=11)
    ax.tick_params(colors='white', labelsize=10)
    ax.spines['bottom'].set_color('#555')
    ax.spines['left'].set_color('#555')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#333', linestyle='--', linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)

    # Right: Dependency distribution pie
    ax2 = axes[1]
    ax2.set_facecolor('#16213e')

    raw  = metrics.get('raw_count', 0)
    war  = metrics.get('war_count', 0)
    waw  = metrics.get('waw_count', 0)
    mem  = metrics.get('mem_dep_count', 0)

    dep_labels = ['RAW\n(True)', 'WAR\n(Anti)', 'WAW\n(Output)', 'Memory']
    dep_values = [raw, war, waw, mem]
    dep_colors = ['#E74C3C', '#F39C12', '#8E44AD', '#1ABC9C']

    # Filter out zeros
    filtered = [(l, v, c) for l, v, c in zip(dep_labels, dep_values, dep_colors) if v > 0]
    if filtered:
        fl, fv, fc = zip(*filtered)
        wedges, texts, autotexts = ax2.pie(
            fv, labels=fl, colors=fc, autopct='%1.1f%%',
            startangle=90, pctdistance=0.8,
            textprops={'color': 'white', 'fontsize': 9},
            wedgeprops={'edgecolor': '#1a1a2e', 'linewidth': 2}
        )
        for at in autotexts:
            at.set_color('white')
            at.set_fontsize(9)
    ax2.set_title('Dependency Distribution', color='white', fontsize=14,
                  fontweight='bold', pad=15)

    plt.suptitle(
        f'ILP Analysis Summary   |   Total Instructions: {metrics.get("total_instructions",0):,}   '
        f'|   Critical Path: {metrics.get("critical_path_cycles",0)} cycles',
        color='white', fontsize=11, y=0.98
    )

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    outpath = os.path.join(outdir, 'ilp_comparison.png')
    plt.savefig(outpath, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"[Visualizer] Saved: {outpath}")

# ============================================================
# CHART 2: GANTT / PARALLEL EXECUTION TIMELINE
# ============================================================

def plot_gantt(timeline, outdir, max_cycles=100, max_rows=200):
    if not timeline:
        return

    # Filter to first max_cycles cycles
    filtered = [r for r in timeline if r['hw_start'] < max_cycles][:max_rows]
    if not filtered:
        return

    fig, (ax_hw, ax_sw) = plt.subplots(2, 1, figsize=(16, 10))
    fig.patch.set_facecolor('#1a1a2e')

    def draw_gantt(ax, rows, start_key, end_key, title):
        ax.set_facecolor('#16213e')
        for i, row in enumerate(rows):
            s = row[start_key]
            e = row[end_key]
            cat = row['category']
            color = CATEGORY_COLORS.get(cat, '#95A5A6')
            ax.barh(i, e - s, left=s, height=0.7,
                    color=color, edgecolor='#1a1a2e', linewidth=0.3, alpha=0.85)

        ax.set_title(title, color='white', fontsize=12, fontweight='bold')
        ax.set_xlabel('Cycle', color='white', fontsize=10)
        ax.set_ylabel('Instruction #', color='white', fontsize=10)
        ax.tick_params(colors='white', labelsize=8)
        ax.spines['bottom'].set_color('#555')
        ax.spines['left'].set_color('#555')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.xaxis.grid(True, color='#333', linestyle='--', linewidth=0.4, alpha=0.7)
        ax.set_xlim(0, max_cycles)

        # Legend
        patches = [mpatches.Patch(color=c, label=k) for k, c in CATEGORY_COLORS.items()]
        ax.legend(handles=patches, loc='upper right',
                  framealpha=0.3, facecolor='#16213e',
                  labelcolor='white', fontsize=7, ncol=3)

    draw_gantt(ax_hw, filtered, 'hw_start', 'hw_end',
               f'Hardware Schedule (OOO) — first {max_cycles} cycles, {len(filtered)} instructions')
    draw_gantt(ax_sw, filtered, 'sw_start', 'sw_end',
               f'Software Schedule (Compiler) — first {max_cycles} cycles, {len(filtered)} instructions')

    plt.tight_layout()
    outpath = os.path.join(outdir, 'execution_timeline.png')
    plt.savefig(outpath, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"[Visualizer] Saved: {outpath}")

# ============================================================
# CHART 3: PARALLELISM HISTOGRAM (instructions per cycle)
# ============================================================

def plot_cycle_histogram(timeline, outdir, max_cycles=200):
    if not timeline:
        return

    # Count instructions per cycle for HW schedule
    hw_counts = {}
    sw_counts = {}
    for row in timeline:
        if row['hw_start'] < max_cycles:
            hw_counts[row['hw_start']] = hw_counts.get(row['hw_start'], 0) + 1
        if row['sw_start'] < max_cycles:
            sw_counts[row['sw_start']] = sw_counts.get(row['sw_start'], 0) + 1

    if not hw_counts:
        return

    cycles = list(range(max_cycles))
    hw_vals = [hw_counts.get(c, 0) for c in cycles]
    sw_vals = [sw_counts.get(c, 0) for c in cycles]

    fig, ax = plt.subplots(figsize=(16, 6))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')

    x = np.array(cycles)
    ax.fill_between(x, hw_vals, alpha=0.4, color='#3498DB', label='HW (OOO)')
    ax.plot(x, hw_vals, color='#3498DB', linewidth=0.8)
    ax.fill_between(x, sw_vals, alpha=0.4, color='#E74C3C', label='SW (Compiler)')
    ax.plot(x, sw_vals, color='#E74C3C', linewidth=0.8)

    avg_hw = np.mean(hw_vals)
    avg_sw = np.mean(sw_vals)
    ax.axhline(avg_hw, color='#3498DB', linestyle='--', linewidth=1,
               label=f'HW avg={avg_hw:.2f}')
    ax.axhline(avg_sw, color='#E74C3C', linestyle='--', linewidth=1,
               label=f'SW avg={avg_sw:.2f}')

    ax.set_title(f'Instruction Parallelism per Cycle (first {max_cycles} cycles)',
                 color='white', fontsize=13, fontweight='bold')
    ax.set_xlabel('Cycle', color='white', fontsize=11)
    ax.set_ylabel('Instructions Issued', color='white', fontsize=11)
    ax.tick_params(colors='white', labelsize=9)
    ax.spines['bottom'].set_color('#555')
    ax.spines['left'].set_color('#555')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#333', linestyle='--', linewidth=0.4, alpha=0.7)
    ax.legend(facecolor='#16213e', labelcolor='white', fontsize=10)

    plt.tight_layout()
    outpath = os.path.join(outdir, 'parallelism_histogram.png')
    plt.savefig(outpath, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"[Visualizer] Saved: {outpath}")

# ============================================================
# CHART 4: OPCODE FREQUENCY BAR CHART
# ============================================================

def plot_opcode_freq(timeline, outdir, top_n=15):
    if not timeline:
        return

    opcode_counts = {}
    for row in timeline:
        op = row['opcode']
        opcode_counts[op] = opcode_counts.get(op, 0) + 1

    sorted_ops = sorted(opcode_counts.items(), key=lambda x: -x[1])[:top_n]
    if not sorted_ops:
        return

    labels, values = zip(*sorted_ops)
    cmap = plt.cm.get_cmap('tab20', len(labels))
    colors = [cmap(i) for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')

    bars = ax.barh(list(reversed(labels)), list(reversed(values)),
                   color=list(reversed(colors)), edgecolor='white', linewidth=0.3)
    for bar, val in zip(bars, reversed(values)):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                f'{val:,}', va='center', color='white', fontsize=8)

    ax.set_title(f'Top {top_n} Opcodes by Dynamic Frequency',
                 color='white', fontsize=13, fontweight='bold')
    ax.set_xlabel('Count', color='white', fontsize=11)
    ax.tick_params(colors='white', labelsize=9)
    ax.spines['bottom'].set_color('#555')
    ax.spines['left'].set_color('#555')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.xaxis.grid(True, color='#333', linestyle='--', linewidth=0.4, alpha=0.7)
    ax.set_axisbelow(True)

    plt.tight_layout()
    outpath = os.path.join(outdir, 'opcode_frequency.png')
    plt.savefig(outpath, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print(f"[Visualizer] Saved: {outpath}")

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='ILP Analyzer Visualizer')
    parser.add_argument('--metrics',  default='output/metrics.json',
                        help='Path to metrics.json')
    parser.add_argument('--timeline', default='output/timeline.csv',
                        help='Path to timeline.csv')
    parser.add_argument('--outdir',   default='output',
                        help='Output directory for PNG files')
    parser.add_argument('--max-cycles', type=int, default=200,
                        help='Max cycles to show in timeline (default: 200)')
    parser.add_argument('--max-gantt', type=int, default=300,
                        help='Max instructions to show in Gantt chart')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    print("\n╔═══════════════════════════════════════════╗")
    print("║       ILP Analyzer — Visualizer           ║")
    print("╚═══════════════════════════════════════════╝\n")

    metrics  = load_metrics(args.metrics)
    timeline = load_timeline(args.timeline)

    print(f"[Visualizer] Loaded {len(timeline)} timeline records")

    print("[Visualizer] Generating ILP comparison chart...")
    plot_ilp_comparison(metrics, args.outdir)

    print("[Visualizer] Generating Gantt chart...")
    plot_gantt(timeline, args.outdir, max_cycles=args.max_cycles,
               max_rows=args.max_gantt)

    print("[Visualizer] Generating parallelism histogram...")
    plot_cycle_histogram(timeline, args.outdir, max_cycles=args.max_cycles)

    print("[Visualizer] Generating opcode frequency chart...")
    plot_opcode_freq(timeline, args.outdir)

    print(f"\n✓ All visualizations saved to: {args.outdir}/\n")
    print("Files generated:")
    for f in ['ilp_comparison.png', 'execution_timeline.png',
              'parallelism_histogram.png', 'opcode_frequency.png']:
        fp = os.path.join(args.outdir, f)
        if os.path.exists(fp):
            size = os.path.getsize(fp)
            print(f"  {fp}  ({size//1024} KB)")

if __name__ == '__main__':
    main()
