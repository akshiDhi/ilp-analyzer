#pragma once
/*
 * scheduler.hpp — ILP Scheduling Simulation
 * ==========================================
 * Implements two instruction scheduling models:
 *
 * A) SOFTWARE REORDERING (Compiler Scheduling):
 *    Simulates what a compiler's list scheduler would produce.
 *    - Instructions are reordered within a scheduling region (basic block)
 *    - True data dependencies (RAW) must be respected
 *    - Anti-deps (WAR) and output deps (WAW) constrain but can be eliminated
 *      via register renaming — we simulate ideal renaming
 *    - Finite in-order issue, infinite functional units
 *    - Uses List Scheduling with ALAP priority heuristic
 *
 * B) HARDWARE REORDERING (Out-of-Order Execution):
 *    Simulates an ideal OOO processor:
 *    - Infinite reorder buffer, infinite issue queue
 *    - Infinite functional units (no structural hazards)
 *    - Perfect memory disambiguation
 *    - Only true RAW data dependencies limit parallelism
 *    - This gives the THEORETICAL MAXIMUM ILP for the given instruction mix
 *
 * RESULT:
 *    The ILP computed by hardware reordering equals the theoretical ILP:
 *        ILP = Total Instructions / Critical Path Length (in cycles)
 *
 * SOFTWARE ILP ≤ HARDWARE ILP (always)
 * Because software cannot see across branch mispredictions and has finite
 * scheduling window, while our hardware model is idealized.
 */

#ifndef ILP_SCHEDULER_HPP
#define ILP_SCHEDULER_HPP

#include <iomanip>
#include "dependency_graph.hpp"
#include "trace_record.hpp"
#include <vector>
#include <queue>
#include <functional>
#include <algorithm>
#include <numeric>
#include <map>
#include <iostream>

// ============================================================
// SCHEDULE RESULT
// ============================================================

struct ScheduleResult {
    // cycle → list of node indices issued in that cycle
    std::map<int64_t, std::vector<uint32_t>> cycle_map;

    int64_t total_cycles = 0;
    double  ilp = 0.0;   // = total_instructions / total_cycles
    int64_t max_parallel = 0;  // max instructions in any single cycle

    uint64_t total_instructions = 0;

    void compute() {
        total_cycles = cycle_map.empty() ? 0 : cycle_map.rbegin()->first + 1;
        max_parallel = 0;
        for (auto& kv : cycle_map) {
            max_parallel = std::max(max_parallel, (int64_t)kv.second.size());
        }
        ilp = (total_cycles > 0) ?
              static_cast<double>(total_instructions) / total_cycles : 0.0;
    }
};

// ============================================================
// HARDWARE SCHEDULER (Ideal OOO)
// ============================================================
// Simulates a processor with:
//   - Unlimited reorder buffer
//   - Unlimited issue queue
//   - Unlimited functional units
//   - Perfect branch prediction and memory disambiguation
//   - Only RAW (true data) dependencies block issue
//
// This gives the THEORETICAL UPPER BOUND on achievable ILP.
//
// Algorithm: ASAP scheduling — each instruction is issued as soon as
// all its true (RAW) dependencies have completed.

class HardwareScheduler {
public:
    static ScheduleResult schedule(DependencyGraph& graph) {
        size_t N = graph.nodes.size();
        ScheduleResult result;
        result.total_instructions = N;

        if (N == 0) return result;

        // finish_cycle[i] = cycle at which node i finishes execution
        std::vector<int64_t> finish_cycle(N, 0);

        for (size_t i = 0; i < N; ++i) {
            auto& node = graph.nodes[i];

            // ASAP start = max finish time among RAW predecessors
            int64_t start = 0;
            for (const auto& edge : node.in_edges) {
                if (edge.is_true_dep()) {
                    uint32_t pred_idx = edge.from_dyn_id;
                    if (pred_idx < N) {
                        start = std::max(start, finish_cycle[pred_idx]);
                    }
                }
            }

            node.asap_cycle = start;
            node.scheduled_cycle = static_cast<uint64_t>(start);
            finish_cycle[i] = start + node.latency;

            result.cycle_map[start].push_back(static_cast<uint32_t>(i));
        }

        result.compute();
        return result;
    }
};

// ============================================================
// SOFTWARE SCHEDULER (List Scheduler with Register Renaming)
// ============================================================
// Simulates compiler scheduling:
//   - Instructions are scheduled in-order within each scheduling region
//   - Scheduling region: window of WINDOW_SIZE instructions at a time
//     (simulating the compiler's limited look-ahead)
//   - Priority: instructions on the critical path go first (ALAP heuristic)
//   - Register renaming eliminates WAR and WAW deps (only RAW remains)
//   - Single-issue per cycle (conservative), or configurable

class SoftwareScheduler {
public:
    struct Config {
        int  window_size = 64;    // Look-ahead window (instructions)
        int  issue_width = 4;     // Instructions issued per cycle (superscalar)
        bool rename_regs = true;  // Simulate register renaming
        bool verbose = false;
    };

    static ScheduleResult schedule(DependencyGraph& graph,
                                    const Config& cfg ) {
        size_t N = graph.nodes.size();
        ScheduleResult result;
        result.total_instructions = N;

        if (N == 0) return result;

        // Compute ALAP priorities for all nodes
        computeALAP(graph);

        // finish_cycle[i] = when node i's output is ready
        std::vector<int64_t> finish_cycle(N, -1);
        // done[i] = has node i been scheduled
        std::vector<bool> done(N, false);

        int64_t current_cycle = 0;
        size_t  scheduled_count = 0;
        size_t  window_start = 0;  // start of current scheduling window

        while (scheduled_count < N) {
            // Build ready list from window [window_start, window_start+window_size)
            size_t window_end = std::min(window_start + (size_t)cfg.window_size, N);

            // Ready: not done, all RAW predecessors finished before current_cycle
            std::vector<uint32_t> ready;
            for (size_t i = window_start; i < window_end; ++i) {
                if (done[i]) continue;
                bool all_ready = true;
                for (const auto& edge : graph.nodes[i].in_edges) {
                    if (!cfg.rename_regs || edge.is_true_dep()) {
                        uint32_t pred = edge.from_dyn_id;
                        if (pred < N && !done[pred]) {
                            all_ready = false;
                            break;
                        }
                        if (pred < N && finish_cycle[pred] > current_cycle) {
                            all_ready = false;
                            break;
                        }
                    }
                }
                if (all_ready) ready.push_back(static_cast<uint32_t>(i));
            }

            if (ready.empty()) {
                // No instruction ready — advance cycle
                ++current_cycle;
                continue;
            }

            // Sort ready list by ALAP priority (lower ALAP = more critical)
            std::sort(ready.begin(), ready.end(), [&](uint32_t a, uint32_t b) {
                return graph.nodes[a].alap_cycle < graph.nodes[b].alap_cycle;
            });

            // Issue up to issue_width instructions
            int issued = 0;
            for (uint32_t nid : ready) {
                if (issued >= cfg.issue_width) break;

                graph.nodes[nid].scheduled_cycle = current_cycle;
                finish_cycle[nid] = current_cycle + graph.nodes[nid].latency;
                done[nid] = true;
                result.cycle_map[current_cycle].push_back(nid);
                ++issued;
                ++scheduled_count;
            }

            // Advance window: skip past all consecutive done nodes
            while (window_start < N && done[window_start]) ++window_start;

            ++current_cycle;
        }

        result.compute();
        return result;
    }
static ScheduleResult schedule(DependencyGraph& graph) {
    return schedule(graph, Config{});
}
private:
    // Compute ALAP (As Late As Possible) cycle for each node.
    // ALAP = critical path length - (longest path from node to any sink)
    // Used as scheduling priority: lower ALAP → on critical path → issue first.
    static void computeALAP(DependencyGraph& graph) {
        size_t N = graph.nodes.size();
        // Process in reverse topological order (reverse program order for DAG)
        std::vector<int64_t> alap(N, 0);

        for (int i = (int)N - 1; i >= 0; --i) {
            int64_t max_succ = 0;
            for (uint32_t succ_idx : graph.nodes[i].succs) {
                if (succ_idx < N) {
                    int64_t succ_alap = alap[succ_idx] + graph.nodes[succ_idx].latency;
                    max_succ = std::max(max_succ, succ_alap);
                }
            }
            alap[i] = max_succ;
            graph.nodes[i].alap_cycle = alap[i];
        }
    }
};

// ============================================================
// ILP METRICS COMPUTATION
// ============================================================

inline ILPMetrics computeMetrics(
    const std::vector<TraceRecord>& records,
    const DependencyGraph& graph,
    const ScheduleResult& hw_result,
    const ScheduleResult& sw_result)
{
    ILPMetrics m;
    m.total_instructions = records.size();

    // Critical path (from hardware schedule — ideal OOO)
    m.critical_path_length = hw_result.total_cycles;
    m.theoretical_ilp = hw_result.ilp;
    m.avg_parallel_per_cycle = hw_result.max_parallel > 0 ?
        static_cast<double>(m.total_instructions) / hw_result.total_cycles : 0.0;

    // Dependency counts
    m.raw_count = graph.countRAW();
    m.war_count = graph.countWAR();
    m.waw_count = graph.countWAW();
    m.mem_dep_count = 0;
    for (auto& e : graph.all_edges) {
        if (e.type == DepType::MEM_RAW ||
            e.type == DepType::MEM_WAW ||
            e.type == DepType::MEM_WAR) ++m.mem_dep_count;
    }

    // Dependency density = edges / nodes
    m.dependency_density = (m.total_instructions > 0) ?
        static_cast<double>(graph.all_edges.size()) / m.total_instructions : 0.0;

    // Max parallelism
    m.max_parallelism = hw_result.max_parallel;

    // ILP under different models
    m.hw_reorder_ilp = hw_result.ilp;
    m.sw_reorder_ilp = sw_result.ilp;

    return m;
}

inline void ILPMetrics::print(std::ostream& out) const {
    out << "\n";
    out << "╔══════════════════════════════════════════════════════╗\n";
    out << "║          ILP ANALYSIS REPORT                        ║\n";
    out << "╠══════════════════════════════════════════════════════╣\n";
    out << "║  Total Instructions     : " << std::setw(10) << total_instructions
                                         << "              ║\n";
    out << "║  Critical Path Length   : " << std::setw(10) << critical_path_length
                                         << " cycles          ║\n";
    out << "╠══════════════════════════════════════════════════════╣\n";
    out << "║  Theoretical ILP        : " << std::setw(10) << std::fixed
        << std::setprecision(3) << theoretical_ilp << "              ║\n";
    out << "║  HW Reorder ILP (OOO)   : " << std::setw(10) << hw_reorder_ilp
                                         << "              ║\n";
    out << "║  SW Reorder ILP (Cpl)   : " << std::setw(10) << sw_reorder_ilp
                                         << "              ║\n";
    out << "║  Max Parallelism        : " << std::setw(10) << max_parallelism
                                         << " ins/cycle       ║\n";
    out << "╠══════════════════════════════════════════════════════╣\n";
    out << "║  RAW Dependencies       : " << std::setw(10) << raw_count
                                         << "              ║\n";
    out << "║  WAR Dependencies       : " << std::setw(10) << war_count
                                         << "              ║\n";
    out << "║  WAW Dependencies       : " << std::setw(10) << waw_count
                                         << "              ║\n";
    out << "║  Memory Dependencies    : " << std::setw(10) << mem_dep_count
                                         << "              ║\n";
    out << "║  Dependency Density     : " << std::setw(10) << std::fixed
        << std::setprecision(3) << dependency_density << "              ║\n";
    out << "╚══════════════════════════════════════════════════════╝\n\n";
}

#endif // ILP_SCHEDULER_HPP
