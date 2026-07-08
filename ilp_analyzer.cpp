/*
 * ilp_analyzer.cpp — Main ILP Analysis Tool
 * ==========================================
 * Reads a Pin-generated instruction trace, builds a dynamic dependency graph,
 * computes ILP metrics, runs scheduling simulation, and generates reports.
 *
 * Usage:
 *   ./ilp_analyzer -i trace.out [-o output_dir] [options]
 *
 * Authors: Akshita Dhiman (2024CSB1098), Saloni Mahajan (2024CSB1149)
 */

#include "trace_parser.hpp"
#include "dependency_graph.hpp"
#include "scheduler.hpp"
#include "trace_record.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <map>
#include <algorithm>

namespace fs = std::filesystem;

// ============================================================
// CLI ARGUMENTS
// ============================================================

struct Config {
    std::string input_trace    = "trace.out";
    std::string output_dir     = "output";
    size_t      max_records    = 1000000;   // Process up to 1M instructions
    bool        track_memory   = true;
    bool        verbose        = false;
    bool        gen_dot        = true;
    bool        gen_timeline   = true;
    bool        gen_report     = true;
    int         sw_window      = 64;        // Compiler scheduling window
    int         sw_issue_width = 4;         // Superscalar issue width
    size_t      dot_limit      = 200;       // Max nodes in DOT output (for readability)
};

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -i <file>    Input trace file (default: trace.out)\n"
              << "  -o <dir>     Output directory (default: output)\n"
              << "  -n <count>   Max instructions to analyze (default: 1000000)\n"
              << "  -w <size>    SW scheduling window size (default: 64)\n"
              << "  -s <width>   SW issue width (default: 4)\n"
              << "  --no-mem     Disable memory dependency tracking\n"
              << "  --no-dot     Skip DOT/Graphviz output\n"
              << "  --no-tl      Skip timeline output\n"
              << "  -v           Verbose output\n"
              << "  -h           Show this help\n\n"
              << "Example:\n"
              << "  ./ilp_analyzer -i trace.out -o output/ -n 500000\n";
}

Config parseArgs(int argc, char* argv[]) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) cfg.input_trace = argv[++i];
        else if (!strcmp(argv[i], "-o") && i+1 < argc) cfg.output_dir = argv[++i];
        else if (!strcmp(argv[i], "-n") && i+1 < argc) cfg.max_records = std::stoull(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i+1 < argc) cfg.sw_window = std::stoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i+1 < argc) cfg.sw_issue_width = std::stoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-mem"))  cfg.track_memory = false;
        else if (!strcmp(argv[i], "--no-dot"))  cfg.gen_dot = false;
        else if (!strcmp(argv[i], "--no-tl"))   cfg.gen_timeline = false;
        else if (!strcmp(argv[i], "-v"))        cfg.verbose = true;
        else if (!strcmp(argv[i], "-h")) { printUsage(argv[0]); exit(0); }
        else { std::cerr << "Unknown option: " << argv[i] << "\n"; printUsage(argv[0]); exit(1); }
    }
    return cfg;
}

// ============================================================
// DOT GRAPH GENERATION
// Generates Graphviz DOT file for the dependency graph.
// For large traces we limit to the first N nodes for readability.
// ============================================================

void generateDOT(const DependencyGraph& graph,
                 const std::vector<TraceRecord>& records,
                 const ScheduleResult& hw_sched,
                 const std::string& outpath,
                 size_t limit) {
    std::ofstream out(outpath);
    if (!out.is_open()) {
        std::cerr << "[DOT] Cannot open: " << outpath << "\n";
        return;
    }

    size_t N = std::min(graph.nodes.size(), limit);

    out << "digraph DependencyGraph {\n";
    out << "  rankdir=TB;\n";
    out << "  graph [fontname=\"Courier\", label=\"Dynamic Dependency Graph\\n"
        << N << " of " << graph.nodes.size() << " instructions shown\", "
        << "labelloc=t, fontsize=14];\n";
    out << "  node [shape=box, fontname=\"Courier\", fontsize=9, style=filled];\n";
    out << "  edge [fontname=\"Courier\", fontsize=8];\n\n";

    // Write nodes
    for (size_t i = 0; i < N; ++i) {
        const auto& node = graph.nodes[i];
        const auto& rec  = *node.rec;

        // Color by category
        std::string fillcolor;
        switch (rec.category) {
            case TraceRecord::Category::ARITHMETIC: fillcolor = "#AED6F1"; break;
            case TraceRecord::Category::LOGIC:      fillcolor = "#A9DFBF"; break;
            case TraceRecord::Category::MOVE:       fillcolor = "#F9E79F"; break;
            case TraceRecord::Category::BRANCH:     fillcolor = "#F1948A"; break;
            case TraceRecord::Category::FLOAT:      fillcolor = "#D2B4DE"; break;
            case TraceRecord::Category::COMPARE:    fillcolor = "#FAD7A0"; break;
            default:                                fillcolor = "#EAECEE"; break;
        }

        // Node label: dyn_id, opcode, src→dst regs
        std::string src, dst;
        for (auto& r : rec.src_regs) { if (!src.empty()) src+=","; src+=r; }
        for (auto& r : rec.dst_regs) { if (!dst.empty()) dst+=","; dst+=r; }

        out << "  n" << i << " [label=\"#" << rec.dyn_id
            << "\\n" << rec.opcode;
        if (!src.empty()) out << "\\n[" << src << "]";
        if (!dst.empty()) out << "→[" << dst << "]";
        out << "\\ncyc:" << node.asap_cycle
            << "\", fillcolor=\"" << fillcolor << "\"];\n";
    }

    out << "\n";

    // Write edges
    for (const auto& edge : graph.all_edges) {
        uint32_t from = edge.from_dyn_id;
        uint32_t to   = edge.to_dyn_id;
        if (from >= N || to >= N) continue;

        // Edge style by dependency type
        std::string color, style, label;
        switch (edge.type) {
            case DepType::RAW:
                color="\"#E74C3C\""; style="solid";   label="RAW"; break;
            case DepType::WAR:
                color="\"#F39C12\""; style="dashed";  label="WAR"; break;
            case DepType::WAW:
                color="\"#8E44AD\""; style="dotted";  label="WAW"; break;
            case DepType::MEM_RAW:
                color="\"#C0392B\""; style="solid";   label="MEM_RAW"; break;
            case DepType::MEM_WAR:
                color="\"#E67E22\""; style="dashed";  label="MEM_WAR"; break;
            case DepType::MEM_WAW:
                color="\"#9B59B6\""; style="dotted";  label="MEM_WAW"; break;
            default:
                color="black"; style="solid";         label="?"; break;
        }

        out << "  n" << from << " -> n" << to
            << " [color=" << color
            << ", style=" << style
            << ", label=\"" << label << "\\n" << edge.reg << "\"];\n";
    }

    // Add rank clusters by scheduled cycle (first 20 cycles)
    std::map<int64_t, std::vector<size_t>> cycle_groups;
    for (size_t i = 0; i < N; ++i) {
        cycle_groups[graph.nodes[i].asap_cycle].push_back(i);
    }
    for (auto& [cycle, nodes_in_cycle] : cycle_groups) {
        if (cycle > 20) break;
        out << "  { rank=same;";
        for (size_t ni : nodes_in_cycle) out << " n" << ni << ";";
        out << " }\n";
    }

    out << "}\n";
    std::cout << "[DOT] Written: " << outpath << "\n";
}

// ============================================================
// TIMELINE CSV GENERATION
// Generates a CSV suitable for Gantt chart visualization.
// ============================================================

void generateTimelineCSV(const DependencyGraph& graph,
                         const ScheduleResult& hw_sched,
                         const ScheduleResult& sw_sched,
                         const std::string& outpath) {
    std::ofstream out(outpath);
    if (!out.is_open()) { std::cerr << "[Timeline] Cannot open: " << outpath << "\n"; return; }

    out << "node_id,dyn_id,opcode,category,hw_start_cycle,hw_end_cycle,sw_start_cycle,sw_end_cycle,latency\n";

    for (size_t i = 0; i < graph.nodes.size(); ++i) {
        const auto& node = graph.nodes[i];
        const auto& rec  = *node.rec;

        std::string cat;
        switch (rec.category) {
            case TraceRecord::Category::ARITHMETIC: cat="ARITH";    break;
            case TraceRecord::Category::LOGIC:      cat="LOGIC";    break;
            case TraceRecord::Category::MOVE:       cat="MOVE";     break;
            case TraceRecord::Category::BRANCH:     cat="BRANCH";   break;
            case TraceRecord::Category::FLOAT:      cat="FLOAT";    break;
            case TraceRecord::Category::COMPARE:    cat="COMPARE";  break;
            default:                                cat="OTHER";    break;
        }

        int64_t hw_start = node.asap_cycle;
        int64_t hw_end   = hw_start + node.latency;
        // SW schedule info from nodes (set during scheduling)
        int64_t sw_start = static_cast<int64_t>(node.scheduled_cycle);
        int64_t sw_end   = sw_start + node.latency;

        out << i << ","
            << rec.dyn_id << ","
            << rec.opcode << ","
            << cat << ","
            << hw_start << ","
            << hw_end << ","
            << sw_start << ","
            << sw_end << ","
            << node.latency << "\n";
    }

    std::cout << "[Timeline] Written: " << outpath << "\n";
}

// ============================================================
// TEXT REPORT GENERATION
// ============================================================

void generateReport(const ILPMetrics& m,
                    const Config& cfg,
                    const ScheduleResult& hw_sched,
                    const ScheduleResult& sw_sched,
                    const std::string& outpath) {
    std::ofstream out(outpath);
    if (!out.is_open()) { std::cerr << "[Report] Cannot open: " << outpath << "\n"; return; }

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);

    out << "=================================================================\n";
    out << " ILP ANALYZER — FULL ANALYSIS REPORT\n";
    out << " Project: Instruction Level Parallelism (ILP) Analyzer\n";
    out << " Authors: Akshita Dhiman (2024CSB1098), Saloni Mahajan (2024CSB1149)\n";
    out << "=================================================================\n\n";

    out << "Input Trace  : " << cfg.input_trace << "\n";
    out << "Analysis Date: " << std::ctime(&t);
    out << "Max Records  : " << cfg.max_records << "\n";
    out << "Mem Tracking : " << (cfg.track_memory ? "ON" : "OFF") << "\n";
    out << "SW Window    : " << cfg.sw_window << " instructions\n";
    out << "SW Issue W   : " << cfg.sw_issue_width << " instructions/cycle\n\n";

    out << "-----------------------------------------------------------------\n";
    out << " INSTRUCTION COUNTS\n";
    out << "-----------------------------------------------------------------\n";
    out << "Total Dynamic Instructions  : " << m.total_instructions << "\n";

    out << "\n";
    out << "-----------------------------------------------------------------\n";
    out << " DEPENDENCY ANALYSIS\n";
    out << "-----------------------------------------------------------------\n";
    out << "RAW (Read After Write) deps  : " << m.raw_count
        << "  [TRUE DEPENDENCIES — limit ILP]\n";
    out << "WAR (Write After Read) deps  : " << m.war_count
        << "  [ANTI-DEPS — can be eliminated by renaming]\n";
    out << "WAW (Write After Write) deps : " << m.waw_count
        << "  [OUTPUT DEPS — can be eliminated by renaming]\n";
    out << "Memory-based dependencies    : " << m.mem_dep_count << "\n";
    out << "Total edges in dep graph     : "
        << m.raw_count + m.war_count + m.waw_count << "\n";
    out << "Dependency density (e/n)     : " << std::fixed << std::setprecision(3)
        << m.dependency_density << "\n\n";

    out << "-----------------------------------------------------------------\n";
    out << " ILP ESTIMATION\n";
    out << "-----------------------------------------------------------------\n";
    out << "Formula: ILP = Total Instructions / Critical Path Length (cycles)\n\n";
    out << "Critical Path Length         : " << m.critical_path_length << " cycles\n";
    out << "Theoretical ILP              : " << std::fixed << std::setprecision(3)
        << m.theoretical_ilp << "\n\n";

    out << "Hardware Reordering (OOO):\n";
    out << "  Model: Infinite ROB, infinite functional units,\n";
    out << "         only RAW deps limit parallelism\n";
    out << "  Total cycles                 : " << hw_sched.total_cycles << "\n";
    out << "  ILP (HW model)              : " << std::fixed << std::setprecision(3)
        << m.hw_reorder_ilp << "\n";
    out << "  Max instructions in 1 cycle : " << m.max_parallelism << "\n\n";

    out << "Software Reordering (Compiler Scheduling):\n";
    out << "  Model: List scheduler, window=" << cfg.sw_window
        << ", issue_width=" << cfg.sw_issue_width << "\n";
    out << "         Ideal register renaming (WAR/WAW eliminated)\n";
    out << "  Total cycles                 : " << sw_sched.total_cycles << "\n";
    out << "  ILP (SW model)              : " << std::fixed << std::setprecision(3)
        << m.sw_reorder_ilp << "\n\n";

    out << "-----------------------------------------------------------------\n";
    out << " INTERPRETATION\n";
    out << "-----------------------------------------------------------------\n";
    out << "SW ILP / HW ILP ratio: "
        << std::fixed << std::setprecision(1)
        << (m.hw_reorder_ilp > 0 ? (m.sw_reorder_ilp/m.hw_reorder_ilp*100) : 0)
        << "% of theoretical achieved by compiler scheduling\n";

    if (m.theoretical_ilp < 1.5) {
        out << "=> LOW ILP: Heavy dependency chain. Dominated by sequential deps.\n";
    } else if (m.theoretical_ilp < 4.0) {
        out << "=> MODERATE ILP: Some parallelism available. Mixed dep/indep ratio.\n";
    } else {
        out << "=> HIGH ILP: Good instruction-level parallelism. OOO CPU beneficial.\n";
    }
    out << "\n";

    out << "-----------------------------------------------------------------\n";
    out << " HW SCHEDULE — CYCLE HISTOGRAM (first 50 cycles)\n";
    out << "-----------------------------------------------------------------\n";
    int64_t max_c = 50;
    for (auto& [cycle, ins_list] : hw_sched.cycle_map) {
        if (cycle >= max_c) break;
        out << "Cycle " << std::setw(4) << cycle << ": ";
        int bar_len = std::min((int)ins_list.size(), 80);
        for (int b = 0; b < bar_len; ++b) out << "█";
        out << " (" << ins_list.size() << " ins)\n";
    }
    out << "\n";

    out << "=================================================================\n";
    out << " END OF REPORT\n";
    out << "=================================================================\n";

    std::cout << "[Report] Written: " << outpath << "\n";
}

// ============================================================
// MAIN
// ============================================================

int main(int argc, char* argv[]) {
    Config cfg = parseArgs(argc, argv);

    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════╗\n";
    std::cout << "║       ILP ANALYZER — Dynamic Instruction Analysis        ║\n";
    std::cout << "║  Akshita Dhiman (2024CSB1098) | Saloni Mahajan (2024CSB1149) ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n\n";

    // Create output directory
    fs::create_directories(cfg.output_dir);

    // ---- Step 1: Parse trace ----
    std::cout << "[1/5] Parsing trace: " << cfg.input_trace << "\n";
    auto t0 = std::chrono::high_resolution_clock::now();

    TraceParser::ParseOptions parse_opts;
    parse_opts.max_records = cfg.max_records;
    parse_opts.track_memory = cfg.track_memory;
    parse_opts.verbose = cfg.verbose;

    std::vector<TraceRecord> records;
    try {
        records = TraceParser::parse(cfg.input_trace, parse_opts);
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    double parse_ms = std::chrono::duration<double, std::milli>(t1-t0).count();
    std::cout << "    Parsed " << records.size() << " instructions in "
              << std::fixed << std::setprecision(1) << parse_ms << " ms\n\n";

    if (records.empty()) {
        std::cerr << "ERROR: No instructions parsed from trace file.\n";
        return 1;
    }

    // ---- Step 2: Build dependency graph ----
    std::cout << "[2/5] Building dynamic dependency graph...\n";
    auto t2 = std::chrono::high_resolution_clock::now();

    DependencyGraph graph;
    graph.build(records, cfg.track_memory);

    auto t3 = std::chrono::high_resolution_clock::now();
    double dep_ms = std::chrono::duration<double, std::milli>(t3-t2).count();
    std::cout << "    Nodes: " << graph.nodes.size()
              << "  Edges: " << graph.all_edges.size()
              << "  (" << std::fixed << std::setprecision(1) << dep_ms << " ms)\n";
    std::cout << "    RAW: " << graph.countRAW()
              << "  WAR: " << graph.countWAR()
              << "  WAW: " << graph.countWAW() << "\n\n";

    // ---- Step 3: Hardware (OOO) scheduling ----
    std::cout << "[3/5] Running hardware (OOO) scheduler...\n";
    auto hw_result = HardwareScheduler::schedule(graph);
    std::cout << "    Cycles: " << hw_result.total_cycles
              << "  ILP: " << std::fixed << std::setprecision(3) << hw_result.ilp
              << "  Max parallel: " << hw_result.max_parallel << "\n\n";

    // ---- Step 4: Software (compiler) scheduling ----
    std::cout << "[4/5] Running software (compiler) scheduler...\n";
    SoftwareScheduler::Config sw_cfg;
    sw_cfg.window_size  = cfg.sw_window;
    sw_cfg.issue_width  = cfg.sw_issue_width;
    sw_cfg.rename_regs  = true;
    sw_cfg.verbose      = cfg.verbose;
    // Note: SW scheduler modifies graph node scheduled_cycle fields
    // We need to run it on a separate pass; for now run on same graph
    auto sw_result = SoftwareScheduler::schedule(graph, sw_cfg);
    std::cout << "    Cycles: " << sw_result.total_cycles
              << "  ILP: " << std::fixed << std::setprecision(3) << sw_result.ilp << "\n\n";

    // ---- Step 5: Compute metrics and generate output ----
    std::cout << "[5/5] Computing metrics and generating output...\n";

    ILPMetrics metrics = computeMetrics(records, graph, hw_result, sw_result);
    metrics.print(std::cout);

    // Generate DOT file
    if (cfg.gen_dot) {
        std::string dot_path = cfg.output_dir + "/dependency_graph.dot";
        generateDOT(graph, records, hw_result, dot_path, cfg.dot_limit);
        std::cout << "    To render: dot -Tpng " << dot_path
                  << " -o " << cfg.output_dir << "/dependency_graph.png\n";
    }

    // Generate timeline CSV
    if (cfg.gen_timeline) {
        std::string tl_path = cfg.output_dir + "/timeline.csv";
        generateTimelineCSV(graph, hw_result, sw_result, tl_path);
    }

    // Generate text report
    if (cfg.gen_report) {
        std::string rep_path = cfg.output_dir + "/ilp_report.txt";
        generateReport(metrics, cfg, hw_result, sw_result, rep_path);
    }

    // Write JSON summary
    {
        std::string json_path = cfg.output_dir + "/metrics.json";
        std::ofstream jf(json_path);
        jf << "{\n";
        jf << "  \"total_instructions\": " << metrics.total_instructions << ",\n";
        jf << "  \"critical_path_cycles\": " << metrics.critical_path_length << ",\n";
        jf << "  \"theoretical_ilp\": " << std::fixed << std::setprecision(4)
           << metrics.theoretical_ilp << ",\n";
        jf << "  \"hw_reorder_ilp\": " << metrics.hw_reorder_ilp << ",\n";
        jf << "  \"sw_reorder_ilp\": " << metrics.sw_reorder_ilp << ",\n";
        jf << "  \"raw_count\": " << metrics.raw_count << ",\n";
        jf << "  \"war_count\": " << metrics.war_count << ",\n";
        jf << "  \"waw_count\": " << metrics.waw_count << ",\n";
        jf << "  \"mem_dep_count\": " << metrics.mem_dep_count << ",\n";
        jf << "  \"dependency_density\": " << std::fixed << std::setprecision(4)
           << metrics.dependency_density << ",\n";
        jf << "  \"max_parallelism\": " << metrics.max_parallelism << "\n";
        jf << "}\n";
        std::cout << "[JSON] Written: " << json_path << "\n";
    }

    std::cout << "\n✓ Analysis complete. Results in: " << cfg.output_dir << "/\n\n";
    return 0;
}
