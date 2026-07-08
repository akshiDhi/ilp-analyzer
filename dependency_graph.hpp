#pragma once
/*
 * dependency_graph.hpp — Dynamic dependency graph construction
 * ============================================================
 * Builds a directed acyclic graph (DAG) where:
 *   - Nodes  = dynamic instruction instances (indexed by dyn_id)
 *   - Edges  = RAW / WAR / WAW dependencies between them
 *
 * CRITICAL DESIGN: DYNAMIC (not static) tracking
 * ================================================
 * For a loop executing ADD rax, rbx 100 times:
 *
 *   Static analysis: 1 ADD node, self-loop
 *   Dynamic analysis: 100 ADD nodes, chain of RAW edges
 *       (dyn1.rax → dyn2.rax → dyn3.rax → ... → dyn100.rax)
 *
 * This is the correct model for ILP computation. Static analysis
 * would drastically overestimate ILP for loop-carried dependencies.
 *
 * ALGORITHM:
 * We maintain a "last writer" table: for each register, which was the
 * most recent dynamic instruction that wrote to it?
 * Similarly a "last readers" table: the set of most recent readers.
 *
 * For each new instruction I:
 *   For each src_reg R:
 *     If last_writer[R] exists → RAW edge (last_writer[R] → I)
 *     last_readers[R].insert(I)
 *   For each dst_reg R:
 *     If last_writer[R] exists → WAW edge (last_writer[R] → I)
 *     For each r in last_readers[R] → WAR edge (r → I)
 *     last_writer[R] = I
 *     last_readers[R].clear()
 *
 * Memory dependencies are handled similarly using address ranges.
 */

#ifndef ILP_DEPENDENCY_GRAPH_HPP
#define ILP_DEPENDENCY_GRAPH_HPP

#include "trace_record.hpp"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <map>

// ============================================================
// INSTRUCTION LATENCY TABLE
// Approximate execution latencies in cycles for ILP scheduling.
// Based on Intel Skylake/Ice Lake microarchitecture data.
// ============================================================
static int getLatency(const std::string& opcode) {
    // Map opcode → latency in cycles
    static const std::unordered_map<std::string, int> LAT = {
        // Integer arithmetic
        {"ADD",1},{"SUB",1},{"INC",1},{"DEC",1},{"NEG",1},
        {"AND",1},{"OR",1},{"XOR",1},{"NOT",1},
        {"SHL",1},{"SHR",1},{"SAR",1},{"ROL",1},{"ROR",1},
        {"CMP",1},{"TEST",1},
        {"ADC",1},{"SBB",1},
        {"IMUL",3},{"MUL",3},
        {"IDIV",20},{"DIV",20},  // Approximate
        // Move
        {"MOV",1},{"MOVSX",1},{"MOVZX",1},{"MOVSXD",1},{"LEA",1},
        {"PUSH",1},{"POP",1},{"XCHG",2},
        // Memory (L1 hit assumed)
        {"LOAD",4},{"STORE",1},
        // Branches (predicted correctly)
        {"JMP",1},{"JE",1},{"JNE",1},{"JZ",1},{"JNZ",1},
        {"JL",1},{"JLE",1},{"JG",1},{"JGE",1},
        {"JB",1},{"JBE",1},{"JA",1},{"JAE",1},
        {"CALL",1},{"RET",1},
        // Float (x87)
        {"FADD",3},{"FSUB",3},{"FMUL",3},{"FDIV",10},
        {"FLD",1},{"FST",1},{"FSTP",1},
        // SSE scalar
        {"ADDSS",4},{"SUBSS",4},{"MULSS",4},{"DIVSS",11},
        {"ADDSD",4},{"SUBSD",4},{"MULSD",4},{"DIVSD",14},
        // SSE packed
        {"ADDPS",4},{"SUBPS",4},{"MULPS",4},{"DIVPS",11},
        {"ADDPD",4},{"SUBPD",4},{"MULPD",4},{"DIVPD",14},
        // AVX
        {"VADDPS",4},{"VSUBPS",4},{"VMULPS",4},{"VDIVPS",11},
        {"VADDPD",4},{"VSUBPD",4},{"VMULPD",4},{"VDIVPD",14},
        // Shifts
        {"SHLD",3},{"SHRD",3},
        // Misc
        {"NOP",0},{"PAUSE",40},{"CPUID",100},{"SYSCALL",100},
    };

    auto it = LAT.find(opcode);
    if (it != LAT.end()) return it->second;

    // Memory ops get L1 latency by default
    if (opcode.find("MOV") != std::string::npos) return 1;
    if (opcode.find("LOAD") != std::string::npos) return 4;

    return 1;  // Conservative default
}

// ============================================================
// DEPENDENCY GRAPH
// ============================================================

class DependencyGraph {
public:
    // Node in the dependency graph
    struct Node {
        const TraceRecord* rec;          // Pointer into trace vector
        std::vector<uint32_t> preds;     // Predecessor node indices
        std::vector<uint32_t> succs;     // Successor node indices
        std::vector<DepEdge>  in_edges;  // Incoming dependency edges
        std::vector<DepEdge>  out_edges; // Outgoing dependency edges
        int     latency = 1;             // Execution latency
        int64_t critical_path_len = -1;  // Cached ALAP depth (longest path to end)
        int64_t asap_cycle = 0;          // Earliest possible start cycle (ASAP)
        int64_t alap_cycle = 0;
	uint64_t scheduled_cycle = 0;          // Latest allowable start cycle (ALAP)
    };

    std::vector<Node>         nodes;      // All nodes (index = graph_node_id)
    std::vector<DepEdge>      all_edges;  // All dependency edges

    // Build graph from parsed trace records
    void build(std::vector<TraceRecord>& records, bool track_memory = true) {
        nodes.clear();
        all_edges.clear();

        nodes.reserve(records.size());

        // Maps: register name → last writer node index
        std::unordered_map<std::string, uint32_t> last_writer;

        // Maps: register name → set of last reader node indices
        // We keep all last readers until the register is written again
        std::unordered_map<std::string, std::unordered_set<uint32_t>> last_readers;

        // Memory tracking: address → {last_writer, last_readers}
        // Key: (address / 8) to handle overlapping accesses conservatively
        std::unordered_map<uint64_t, uint32_t> mem_last_writer;
        std::unordered_map<uint64_t, std::unordered_set<uint32_t>> mem_last_readers;

        // Assign node IDs
        for (size_t i = 0; i < records.size(); ++i) {
            records[i].graph_node_id = static_cast<uint32_t>(i);
        }

        // Process each instruction in dynamic program order
        for (size_t idx = 0; idx < records.size(); ++idx) {
            TraceRecord& rec = records[idx];
            uint32_t nid = static_cast<uint32_t>(idx);

            Node node;
            node.rec = &rec;
            node.latency = getLatency(rec.opcode);

            // ---- Register dependencies ----

            // SRC registers: detect RAW from last writer
            for (const auto& reg : rec.src_regs) {
                if (reg.empty() || reg == "-") continue;

                auto wit = last_writer.find(reg);
                if (wit != last_writer.end()) {
                    uint32_t writer_nid = wit->second;
                    if (writer_nid != nid) {
                        addEdge(writer_nid, nid, DepType::RAW, reg,
                                nodes[writer_nid].latency);
                    }
                }
                // Record this as a reader
                last_readers[reg].insert(nid);
            }

            // DST registers: detect WAW and WAR, then update last_writer
            for (const auto& reg : rec.dst_regs) {
                if (reg.empty() || reg == "-") continue;

                // WAW: previous writer → current writer
                auto wit = last_writer.find(reg);
                if (wit != last_writer.end()) {
                    uint32_t prev_writer = wit->second;
                    if (prev_writer != nid) {
                        addEdge(prev_writer, nid, DepType::WAW, reg,
                                nodes[prev_writer].latency);
                    }
                }

                // WAR: all previous readers → current writer
                auto rit = last_readers.find(reg);
                if (rit != last_readers.end()) {
                    for (uint32_t reader_nid : rit->second) {
                        if (reader_nid != nid) {
                            addEdge(reader_nid, nid, DepType::WAR, reg,
                                    nodes[reader_nid].latency);
                        }
                    }
                    rit->second.clear();
                }

                // Update last writer
                last_writer[reg] = nid;
                // Reset readers for this register
                last_readers[reg].clear();
            }

            // ---- Memory dependencies ----
            if (track_memory) {
                // Memory is tracked at 8-byte granularity (address >> 3)
                // This is conservative — overlapping accesses within the same
                // 8-byte chunk are treated as dependent

                if (rec.mem_read && rec.mem_read_addr != 0) {
                    uint64_t key = rec.mem_read_addr >> 3;

                    // RAW: previous store → current load
                    auto mwit = mem_last_writer.find(key);
                    if (mwit != mem_last_writer.end()) {
                        uint32_t prev = mwit->second;
                        if (prev != nid) {
                            addEdge(prev, nid, DepType::MEM_RAW, "__MEM__",
                                    nodes[prev].latency + 4);  // +4 for L1 latency
                        }
                    }
                    mem_last_readers[key].insert(nid);
                }

                if (rec.mem_write && rec.mem_write_addr != 0) {
                    uint64_t key = rec.mem_write_addr >> 3;

                    // WAW: previous store → current store
                    auto mwit = mem_last_writer.find(key);
                    if (mwit != mem_last_writer.end()) {
                        uint32_t prev = mwit->second;
                        if (prev != nid) {
                            addEdge(prev, nid, DepType::MEM_WAW, "__MEM__",
                                    nodes[prev].latency);
                        }
                    }

                    // WAR: previous load → current store
                    auto mrit = mem_last_readers.find(key);
                    if (mrit != mem_last_readers.end()) {
                        for (uint32_t reader_nid : mrit->second) {
                            if (reader_nid != nid) {
                                addEdge(reader_nid, nid, DepType::MEM_WAR,
                                        "__MEM__", nodes[reader_nid].latency);
                            }
                        }
                        mrit->second.clear();
                    }

                    mem_last_writer[key] = nid;
                    mem_last_readers[key].clear();
                }
            }

            nodes.push_back(std::move(node));
        }
    }

    // Count dependencies by type
    size_t countRAW() const {
        size_t n = 0;
        for (auto& e : all_edges)
            if (e.type == DepType::RAW || e.type == DepType::MEM_RAW) ++n;
        return n;
    }
    size_t countWAR() const {
        size_t n = 0;
        for (auto& e : all_edges)
            if (e.type == DepType::WAR || e.type == DepType::MEM_WAR) ++n;
        return n;
    }
    size_t countWAW() const {
        size_t n = 0;
        for (auto& e : all_edges)
            if (e.type == DepType::WAW || e.type == DepType::MEM_WAW) ++n;
        return n;
    }

    // Compute critical path length (in cycles) using longest-path DP on the DAG.
    // Returns the length of the critical path (max number of cycles from any
    // source node to any sink node following true dependencies only).
    //
    // ALGORITHM: Since nodes are in topological order (dynamic program order
    // with forward edges only), a single forward DP suffices.
    int64_t computeCriticalPath() {
        size_t N = nodes.size();
        std::vector<int64_t> dp(N, 0);  // dp[i] = earliest finish cycle of node i

        for (size_t i = 0; i < N; ++i) {
            // ASAP start = max finish time of all true-dep predecessors
            int64_t start = 0;
            for (const auto& e : nodes[i].in_edges) {
                if (e.is_true_dep()) {
                    uint32_t pred = e.from_dyn_id;  // This is graph node index here
                    // Find pred node index
                    // (edge stores graph_node_id of predecessor)
                    if (pred < N) {
                        start = std::max(start, dp[pred]);
                    }
                }
            }
            nodes[i].asap_cycle = start;
            dp[i] = start + nodes[i].latency;
        }

        int64_t critical = *std::max_element(dp.begin(), dp.end());
        return critical;
    }

private:
    void addEdge(uint32_t from, uint32_t to, DepType type,
                 const std::string& reg, int latency) {
        DepEdge edge;
        edge.from_dyn_id = from;  // graph node index
        edge.to_dyn_id   = to;
        edge.type        = type;
        edge.reg         = reg;
        edge.latency     = latency;

        nodes[from].succs.push_back(to);
        nodes[from].out_edges.push_back(edge);
        nodes[to].preds.push_back(from);
        nodes[to].in_edges.push_back(edge);
        all_edges.push_back(edge);
    }
};

#endif // ILP_DEPENDENCY_GRAPH_HPP
