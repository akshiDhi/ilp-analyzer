/*
 * ILP Tracer - Intel PinKit Instrumentation Client
 * ===================================================
 * Project: Instruction Level Parallelism (ILP) Analyzer
 * Authors: Akshita Dhiman (2024CSB1098), Saloni Mahajan (2024CSB1149)
 *
 * DESIGN RATIONALE:
 * This PinTool instruments a target binary at runtime, recording every
 * dynamically executed instruction instance. Unlike static analysis, we
 * capture the ACTUAL execution order including loop iterations, branch
 * outcomes, and runtime register values.
 *
 * KEY INSIGHT: A single static ADD instruction in a loop body executed
 * 1000 times produces 1000 dynamic instruction records — each a separate
 * node in the dependency graph with its own register state.
 *
 * HOW PIN INSTRUMENTATION WORKS:
 * Pin uses Just-In-Time (JIT) compilation to recompile each basic block
 * before execution. During this JIT phase, we inject "analysis calls" —
 * callbacks that fire at runtime when the original instruction executes.
 * This gives us full dynamic visibility with no source code required.
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <iomanip>

// ============================================================
// COMMAND LINE SWITCHES
// ============================================================
KNOB<std::string> KnobOutputFile(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "o",
    "trace.out",
    "Output trace file name"
);

KNOB<UINT64> KnobMaxInstructions(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "ilp_max_ins",
    "10000000",
    "Maximum number of instructions to trace (0 = unlimited)"
);

KNOB<BOOL> KnobTraceMemory(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "trace_mem",
    "1",
    "Trace memory read/write operations"
);

KNOB<BOOL> KnobVerbose(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "verbose",
    "0",
    "Enable verbose output"
);

// ============================================================
// GLOBAL STATE
// ============================================================

// Atomic counter: each dynamic instruction gets a unique monotonic ID.
// This is critical for loop handling — same static PC, different dynamic ID.
static std::atomic<UINT64> g_dynamic_ins_id{0};

// Instruction counter for max-limit enforcement
static std::atomic<UINT64> g_ins_count{0};

// Thread-local storage key for per-thread context
static TLS_KEY g_tls_key = INVALID_TLS_KEY;

// Output file (protected by mutex for multi-thread safety)
static std::ofstream g_trace_file;
static PIN_MUTEX g_file_mutex;

// ============================================================
// TRACE RECORD FORMAT
// ============================================================
// Each line in the output trace file:
// DYN_ID | PC | OPCODE_STR | SRC_REGS | DST_REGS | MEM_READ | MEM_WRITE | THREAD_ID
//
// Field separator: |
// Register list separator within field: ,
// Empty register list: -

struct InstructionRecord {
    UINT64          dyn_id;
    ADDRINT         pc;
    std::string     opcode;
    std::string     src_regs;   // comma-separated register names
    std::string     dst_regs;   // comma-separated register names
    bool            mem_read;
    bool            mem_write;
    THREADID        thread_id;
    ADDRINT         mem_read_addr;
    ADDRINT         mem_write_addr;
    UINT32          mem_read_size;
    UINT32          mem_write_size;
};

// ============================================================
// THREAD-LOCAL CONTEXT
// Per-thread pending record (filled at instrumentation time,
// completed at analysis time when we have runtime values).
// ============================================================
struct ThreadContext {
    ADDRINT     mem_read_addr{0};
    ADDRINT     mem_write_addr{0};
    UINT32      mem_read_size{0};
    UINT32      mem_write_size{0};
    bool        has_mem_read{false};
    bool        has_mem_write{false};
};

// ============================================================
// REGISTER NAME HELPER
// ============================================================
// Pin provides REG_StringShort() but we want concise names.
// We also normalize sub-registers: AL, AH, AX, EAX all map to RAX
// for dependency tracking purposes.
static std::string RegName(REG reg) {
    if (!REG_valid(reg)) return "";
    // Use Pin's full register (not partial) for accurate dependency tracking
    REG full = REG_FullRegName(reg);
    return REG_StringShort(full);
}

// Build comma-separated list of register names from a vector
static std::string BuildRegList(const std::vector<std::string>& regs) {
    if (regs.empty()) return "-";
    std::string result;
    for (size_t i = 0; i < regs.size(); ++i) {
        if (i > 0) result += ",";
        result += regs[i];
    }
    return result;
}

// ============================================================
// ANALYSIS FUNCTIONS
// These execute at runtime for each instrumented instruction.
// ============================================================

// Called for every instruction before it executes.
// 'data' carries the pre-built static info for this instruction site.
struct StaticInsInfo {
    std::string opcode;
    std::string src_regs;
    std::string dst_regs;
    bool        may_read_mem;
    bool        may_write_mem;
};

// We store one StaticInsInfo per unique PC.
// Note: same PC in different loops has same StaticInsInfo but different dyn_id.
static std::unordered_map<ADDRINT, StaticInsInfo*> g_ins_info;
static PIN_MUTEX g_info_mutex;

VOID PIN_FAST_ANALYSIS_CALL
AnalysisFunc_Instruction(ADDRINT pc, THREADID tid) {
    UINT64 count = ++g_ins_count;
    UINT64 max_ins = KnobMaxInstructions.Value();
    if (max_ins > 0 && count > max_ins) {
        // Limit reached — detach Pin gracefully
        PIN_Detach();
        return;
    }

    UINT64 dyn_id = ++g_dynamic_ins_id;

    // Fetch static info for this PC
    PIN_MutexLock(&g_info_mutex);
    auto it = g_ins_info.find(pc);
    if (it == g_ins_info.end()) {
        PIN_MutexUnlock(&g_info_mutex);
        return;
    }
    StaticInsInfo* info = it->second;
    PIN_MutexUnlock(&g_info_mutex);

    // Fetch thread context for memory addresses
    ThreadContext* ctx = static_cast<ThreadContext*>(PIN_GetThreadData(g_tls_key, tid));
    bool mem_read = false, mem_write = false;
    ADDRINT mr_addr = 0, mw_addr = 0;
    UINT32 mr_size = 0, mw_size = 0;
    if (ctx) {
        mem_read = ctx->has_mem_read;
        mem_write = ctx->has_mem_write;
        mr_addr = ctx->mem_read_addr;
        mw_addr = ctx->mem_write_addr;
        mr_size = ctx->mem_read_size;
        mw_size = ctx->mem_write_size;
        ctx->has_mem_read = false;
        ctx->has_mem_write = false;
    }

    // Write record to file (mutex for thread safety)
    PIN_MutexLock(&g_file_mutex);
    g_trace_file
        << dyn_id << "|"
        << "0x" << std::hex << pc << std::dec << "|"
        << info->opcode << "|"
        << info->src_regs << "|"
        << info->dst_regs << "|"
        << (mem_read ? "1" : "0") << "|"
        << (mem_write ? "1" : "0") << "|"
        << tid;
    if (mem_read && KnobTraceMemory.Value()) {
        g_trace_file << "|R:0x" << std::hex << mr_addr << ":" << std::dec << mr_size;
    }
    if (mem_write && KnobTraceMemory.Value()) {
        g_trace_file << "|W:0x" << std::hex << mw_addr << ":" << std::dec << mw_size;
    }
    g_trace_file << "\n";
    PIN_MutexUnlock(&g_file_mutex);
}

// Called before a memory read instruction to capture the address
VOID AnalysisFunc_MemRead(ADDRINT addr, UINT32 size, THREADID tid) {
    ThreadContext* ctx = static_cast<ThreadContext*>(PIN_GetThreadData(g_tls_key, tid));
    if (ctx) {
        ctx->mem_read_addr = addr;
        ctx->mem_read_size = size;
        ctx->has_mem_read = true;
    }
}

// Called before a memory write instruction to capture the address
VOID AnalysisFunc_MemWrite(ADDRINT addr, UINT32 size, THREADID tid) {
    ThreadContext* ctx = static_cast<ThreadContext*>(PIN_GetThreadData(g_tls_key, tid));
    if (ctx) {
        ctx->mem_write_addr = addr;
        ctx->mem_write_size = size;
        ctx->has_mem_write = true;
    }
}

// ============================================================
// INSTRUMENTATION CALLBACKS
// These run at JIT time (not at runtime) to insert analysis calls.
// ============================================================

VOID Instruction(INS ins, VOID* v) {
    ADDRINT pc = INS_Address(ins);

    // Build static info for this instruction (done once per unique PC)
    PIN_MutexLock(&g_info_mutex);
    if (g_ins_info.find(pc) == g_ins_info.end()) {
        StaticInsInfo* info = new StaticInsInfo();

        // Opcode string
        info->opcode = INS_Mnemonic(ins);

        // Source registers
        std::vector<std::string> src_regs;
        for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i) {
            REG r = INS_RegR(ins, i);
            if (REG_valid(r) && !REG_is_flags(r) && !REG_is_seg(r)) {
                std::string name = RegName(r);
                if (!name.empty()) src_regs.push_back(name);
            }
        }
        // Also capture implicit reads (flags read by conditional branches)
        if (INS_IsControlFlow(ins) && INS_HasFallThrough(ins)) {
            src_regs.push_back("FLAGS");
        }
        info->src_regs = BuildRegList(src_regs);

        // Destination registers
        std::vector<std::string> dst_regs;
        for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i) {
            REG r = INS_RegW(ins, i);
            if (REG_valid(r) && !REG_is_flags(r) && !REG_is_seg(r)) {
                std::string name = RegName(r);
                if (!name.empty()) dst_regs.push_back(name);
            }
        }
        // Instructions that update flags (ADD, SUB, CMP, etc.)
        if (INS_IsValidForIpointAfter(ins)) {
            // Heuristic: arithmetic/logic instructions write FLAGS
            OPCODE op = INS_Opcode(ins);
            if (op == XED_ICLASS_ADD || op == XED_ICLASS_SUB ||
                op == XED_ICLASS_AND || op == XED_ICLASS_OR  ||
                op == XED_ICLASS_XOR || op == XED_ICLASS_CMP ||
                op == XED_ICLASS_TEST|| op == XED_ICLASS_INC ||
                op == XED_ICLASS_DEC || op == XED_ICLASS_NEG ||
                op == XED_ICLASS_IMUL|| op == XED_ICLASS_MUL ||
                op == XED_ICLASS_IDIV|| op == XED_ICLASS_DIV ||
                op == XED_ICLASS_SHL || op == XED_ICLASS_SHR ||
                op == XED_ICLASS_SAR || op == XED_ICLASS_ROL ||
                op == XED_ICLASS_ROR) {
                dst_regs.push_back("FLAGS");
            }
        }
        info->dst_regs = BuildRegList(dst_regs);

        info->may_read_mem  = INS_IsMemoryRead(ins);
        info->may_write_mem = INS_IsMemoryWrite(ins);

        g_ins_info[pc] = info;
    }
    PIN_MutexUnlock(&g_info_mutex);

    // Insert memory capture callbacks BEFORE instruction analysis
    // (so address is captured before AnalysisFunc_Instruction fires)
    if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)AnalysisFunc_MemRead,
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_THREAD_ID,
            IARG_END);
    }
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)AnalysisFunc_MemWrite,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_THREAD_ID,
            IARG_END);
    }

    // Insert main analysis callback
    INS_InsertCall(ins, IPOINT_BEFORE,
        (AFUNPTR)AnalysisFunc_Instruction,
        IARG_FAST_ANALYSIS_CALL,
        IARG_INST_PTR,
        IARG_THREAD_ID,
        IARG_END);
}

// ============================================================
// THREAD MANAGEMENT
// ============================================================

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadContext* ctx = new ThreadContext();
    PIN_SetThreadData(g_tls_key, ctx, tid);
    if (KnobVerbose.Value()) {
        std::cerr << "[ILP Tracer] Thread " << tid << " started\n";
    }
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadContext* ctx = static_cast<ThreadContext*>(PIN_GetThreadData(g_tls_key, tid));
    delete ctx;
    if (KnobVerbose.Value()) {
        std::cerr << "[ILP Tracer] Thread " << tid << " finished\n";
    }
}

// ============================================================
// FINALIZATION
// ============================================================

VOID Fini(INT32 code, VOID* v) {
    g_trace_file.flush();
    g_trace_file.close();

    UINT64 total = g_dynamic_ins_id.load();
    std::cerr << "[ILP Tracer] Trace complete. Total dynamic instructions: "
              << total << "\n";
    std::cerr << "[ILP Tracer] Trace written to: "
              << KnobOutputFile.Value() << "\n";

    // Cleanup static info map
    PIN_MutexLock(&g_info_mutex);
    for (auto& kv : g_ins_info) delete kv.second;
    g_ins_info.clear();
    PIN_MutexUnlock(&g_info_mutex);
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================

INT32 Usage() {
    std::cerr << "ILP Tracer - Intel PinKit-based dynamic instruction tracer\n";
    std::cerr << "Usage: pin -t ilp_tracer.so [options] -- <target_binary> [args]\n\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
    return EXIT_FAILURE;
}

int main(int argc, char* argv[]) {
    // Initialize Pin
    if (PIN_Init(argc, argv)) return Usage();

    // Initialize mutexes
    PIN_MutexInit(&g_file_mutex);
    PIN_MutexInit(&g_info_mutex);

    // Initialize TLS key for per-thread context
    g_tls_key = PIN_CreateThreadDataKey(nullptr);
    if (g_tls_key == INVALID_TLS_KEY) {
        std::cerr << "[ILP Tracer] ERROR: Failed to create TLS key\n";
        return EXIT_FAILURE;
    }

    // Open trace output file
    g_trace_file.open(KnobOutputFile.Value());
    if (!g_trace_file.is_open()) {
        std::cerr << "[ILP Tracer] ERROR: Cannot open output file: "
                  << KnobOutputFile.Value() << "\n";
        return EXIT_FAILURE;
    }

    // Write trace file header
    g_trace_file << "# ILP Analyzer Trace File\n";
    g_trace_file << "# Format: DYN_ID|PC|OPCODE|SRC_REGS|DST_REGS|MEM_READ|MEM_WRITE|THREAD_ID[|R:addr:size][|W:addr:size]\n";
    g_trace_file << "# Generated by ilp_tracer.so (Intel PinKit)\n";
    g_trace_file << "#\n";

    // Register callbacks
    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    std::cerr << "[ILP Tracer] Starting instrumentation...\n";
    std::cerr << "[ILP Tracer] Output: " << KnobOutputFile.Value() << "\n";
    if (KnobMaxInstructions.Value() > 0) {
        std::cerr << "[ILP Tracer] Max instructions: "
                  << KnobMaxInstructions.Value() << "\n";
    }

    // Start the program (never returns)
    PIN_StartProgram();
    return EXIT_SUCCESS;
}
