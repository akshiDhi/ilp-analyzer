#pragma once
/*
 * trace_record.hpp — Shared data structures for trace parsing and analysis
 * =========================================================================
 * Defines the in-memory representation of a dynamic instruction instance
 * and the parsed trace format emitted by ilp_tracer.so.
 *
 * DESIGN NOTE ON LOOPS:
 * The 'dyn_id' field is the critical field for loop correctness.
 * When a static instruction at PC 0x401234 executes 1000 times in a loop,
 * it generates 1000 TraceRecord entries with dyn_ids 1..1000 but same pc.
 * The dependency analyzer operates on dyn_id — never on pc — so each
 * iteration is treated as an independent node in the dataflow graph.
 */

#ifndef ILP_TRACE_RECORD_HPP
#define ILP_TRACE_RECORD_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <ostream>

// ============================================================
// REGISTER REPRESENTATION
// ============================================================
// We normalize register names to full-width equivalents.
// AL/AH/AX/EAX all become "rax" for dependency checking.
// This is correct because a write to EAX clears the upper 32 bits of RAX
// and a write to AX modifies the lower 16 bits of RAX — both create
// RAW dependencies for subsequent reads of any aliased form.

using RegName = std::string;

// Sentinel for memory pseudo-register (used in memory dependency tracking)
constexpr const char* PSEUDO_REG_MEM_READ  = "__MEM_R__";
constexpr const char* PSEUDO_REG_MEM_WRITE = "__MEM_W__";
constexpr const char* PSEUDO_REG_FLAGS     = "flags";

// ============================================================
// TRACE RECORD
// ============================================================

struct TraceRecord {
    uint64_t              dyn_id;        // Unique dynamic instruction ID (monotonic)
    uint64_t              pc;            // Program counter (static address)
    std::string           opcode;        // Instruction mnemonic (e.g., "ADD", "MOV")
    std::vector<RegName>  src_regs;      // Registers READ by this instruction
    std::vector<RegName>  dst_regs;      // Registers WRITTEN by this instruction
    bool                  mem_read;      // True if instruction reads memory
    bool                  mem_write;     // True if instruction writes memory
    uint32_t              thread_id;     // Thread ID
    uint64_t              mem_read_addr; // Memory read address (0 if none)
    uint64_t              mem_write_addr;// Memory write address (0 if none)
    uint32_t              mem_read_size; // Memory read size in bytes
    uint32_t              mem_write_size;// Memory write size in bytes

    // Convenience: instruction category derived from opcode
    enum class Category {
        ARITHMETIC,   // ADD, SUB, MUL, DIV, INC, DEC, NEG, IMUL, IDIV
        LOGIC,        // AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR
        MOVE,         // MOV, MOVSX, MOVZX, LEA, XCHG, PUSH, POP
        COMPARE,      // CMP, TEST
        BRANCH,       // JMP, Jcc, CALL, RET
        FLOAT,        // FADD, FSUB, FMUL, FDIV, FLD, FST, FXCH, ...
        SIMD,         // SSE/AVX instructions
        SYSTEM,       // SYSCALL, SYSRET, INT, CPUID, ...
        MEMORY,       // Explicit load/store (LOAD, STORE — pseudo)
        OTHER
    };

    Category category = Category::OTHER;

    // Derived: is this a control flow instruction?
    bool is_branch = false;
    bool is_call   = false;
    bool is_ret    = false;

    // Cycle assigned during scheduling simulation (filled by scheduler)
    uint64_t scheduled_cycle = 0;

    // Node index in dependency graph (filled by graph builder)
    uint32_t graph_node_id = UINT32_MAX;
};

// ============================================================
// DEPENDENCY TYPES
// ============================================================

enum class DepType {
    RAW,   // Read After Write  — true dependency (data flow)
    WAR,   // Write After Read  — anti-dependency
    WAW,   // Write After Write — output dependency
    MEM_RAW, // Memory-based RAW (load after store to same address)
    MEM_WAW, // Memory-based WAW (store after store to same address)
    MEM_WAR  // Memory-based WAR (store after load from same address)
};

constexpr const char* DepTypeName(DepType t) {
    switch (t) {
        case DepType::RAW:     return "RAW";
        case DepType::WAR:     return "WAR";
        case DepType::WAW:     return "WAW";
        case DepType::MEM_RAW: return "MEM_RAW";
        case DepType::MEM_WAW: return "MEM_WAW";
        case DepType::MEM_WAR: return "MEM_WAR";
        default:               return "UNKNOWN";
    }
}

// ============================================================
// DEPENDENCY EDGE
// ============================================================

struct DepEdge {
    uint64_t    from_dyn_id;    // Producer instruction
    uint64_t    to_dyn_id;      // Consumer instruction
    DepType     type;           // Dependency type
    RegName     reg;            // Register (or memory pseudo-reg) causing dep
    int         latency;        // Estimated execution latency of 'from' (cycles)

    bool is_true_dep() const {
        return type == DepType::RAW || type == DepType::MEM_RAW;
    }
};

// ============================================================
// ILP METRICS
// ============================================================

struct ILPMetrics {
    uint64_t total_instructions = 0;
    uint64_t critical_path_length = 0;  // In cycles
    double   theoretical_ilp = 0.0;     // = total_ins / critical_path
    double   avg_parallel_per_cycle = 0.0;
    uint64_t raw_count = 0;
    uint64_t war_count = 0;
    uint64_t waw_count = 0;
    uint64_t mem_dep_count = 0;
    double   dependency_density = 0.0;  // edges / nodes
    uint64_t independent_pairs = 0;
    uint64_t max_parallelism = 0;       // Max instructions in same cycle
    double   sw_reorder_ilp = 0.0;      // ILP after software reordering
    double   hw_reorder_ilp = 0.0;      // ILP after hardware (OOO) simulation

    void print(std::ostream& out) const;
};

#endif // ILP_TRACE_RECORD_HPP
