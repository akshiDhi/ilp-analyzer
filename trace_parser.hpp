#pragma once
/*
 * trace_parser.hpp — Parser for ilp_tracer.so output files
 * =========================================================
 * Reads the |-delimited trace file and produces a vector of TraceRecord.
 * Normalizes register names to lowercase full-width form for dependency
 * analysis.
 */

#ifndef ILP_TRACE_PARSER_HPP
#define ILP_TRACE_PARSER_HPP

#include "trace_record.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <unordered_map>
#include <regex>

// ============================================================
// REGISTER NORMALIZATION TABLE
// ============================================================
// Maps any x86 register variant to its full 64-bit canonical name.
// This is essential: a RAW from "EAX write" → "RAX read" must be detected.

static const std::unordered_map<std::string, std::string> REG_NORMALIZE = {
    // RAX family
    {"al","rax"},{"ah","rax"},{"ax","rax"},{"eax","rax"},{"rax","rax"},
    // RBX family
    {"bl","rbx"},{"bh","rbx"},{"bx","rbx"},{"ebx","rbx"},{"rbx","rbx"},
    // RCX family
    {"cl","rcx"},{"ch","rcx"},{"cx","rcx"},{"ecx","rcx"},{"rcx","rcx"},
    // RDX family
    {"dl","rdx"},{"dh","rdx"},{"dx","rdx"},{"edx","rdx"},{"rdx","rdx"},
    // RSI family
    {"sil","rsi"},{"si","rsi"},{"esi","rsi"},{"rsi","rsi"},
    // RDI family
    {"dil","rdi"},{"di","rdi"},{"edi","rdi"},{"rdi","rdi"},
    // RSP family
    {"spl","rsp"},{"sp","rsp"},{"esp","rsp"},{"rsp","rsp"},
    // RBP family
    {"bpl","rbp"},{"bp","rbp"},{"ebp","rbp"},{"rbp","rbp"},
    // R8–R15 families
    {"r8b","r8"},{"r8w","r8"},{"r8d","r8"},{"r8","r8"},
    {"r9b","r9"},{"r9w","r9"},{"r9d","r9"},{"r9","r9"},
    {"r10b","r10"},{"r10w","r10"},{"r10d","r10"},{"r10","r10"},
    {"r11b","r11"},{"r11w","r11"},{"r11d","r11"},{"r11","r11"},
    {"r12b","r12"},{"r12w","r12"},{"r12d","r12"},{"r12","r12"},
    {"r13b","r13"},{"r13w","r13"},{"r13d","r13"},{"r13","r13"},
    {"r14b","r14"},{"r14w","r14"},{"r14d","r14"},{"r14","r14"},
    {"r15b","r15"},{"r15w","r15"},{"r15d","r15"},{"r15","r15"},
    // Flags
    {"flags","flags"},{"eflags","flags"},{"rflags","flags"},
    // XMM/YMM/ZMM (SSE/AVX) - map to canonical xmm/ymm/zmm names
    {"xmm0","xmm0"},{"xmm1","xmm1"},{"xmm2","xmm2"},{"xmm3","xmm3"},
    {"xmm4","xmm4"},{"xmm5","xmm5"},{"xmm6","xmm6"},{"xmm7","xmm7"},
    {"ymm0","xmm0"},{"ymm1","xmm1"},{"ymm2","xmm2"},{"ymm3","xmm3"},
    {"ymm4","xmm4"},{"ymm5","xmm5"},{"ymm6","xmm6"},{"ymm7","xmm7"},
    {"zmm0","xmm0"},{"zmm1","xmm1"},{"zmm2","xmm2"},{"zmm3","xmm3"},
};

class TraceParser {
public:
    struct ParseOptions {
        size_t max_records = SIZE_MAX;   // 0 = unlimited
        bool   track_memory = true;      // Track memory dependencies
        bool   verbose = false;
    };

    // Parse a trace file. Returns vector of TraceRecord (in program order).
    static std::vector<TraceRecord> parse(
        const std::string& filename,
        const ParseOptions& opts 
    ) {
        std::ifstream fin(filename);
        if (!fin.is_open()) {
            throw std::runtime_error("Cannot open trace file: " + filename);
        }

        std::vector<TraceRecord> records;
        records.reserve(1 << 20);  // pre-allocate 1M slots

        std::string line;
        size_t line_num = 0;
        size_t skipped = 0;

        while (std::getline(fin, line)) {
            ++line_num;
            if (line.empty() || line[0] == '#') continue;  // header/comment

            try {
                TraceRecord rec = parseLine(line);
                categorize(rec);
                records.push_back(std::move(rec));
            } catch (const std::exception& e) {
                ++skipped;
                if (opts.verbose) {
                    std::cerr << "[Parser] Line " << line_num
                              << " skipped: " << e.what() << "\n";
                }
            }

            if (records.size() >= opts.max_records) break;
        }

        if (opts.verbose) {
            std::cerr << "[Parser] Parsed " << records.size()
                      << " records (" << skipped << " skipped)\n";
        }

        return records;
    }
static std::vector<TraceRecord> parse(
    const std::string& filename
) {
    return parse(filename, ParseOptions{});
}

private:
    // Parse a single trace line into a TraceRecord
    static TraceRecord parseLine(const std::string& line) {
        // Format: DYN_ID|PC|OPCODE|SRC_REGS|DST_REGS|MEM_READ|MEM_WRITE|THREAD_ID[|R:addr:size][|W:addr:size]
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string token;
        while (std::getline(ss, token, '|')) {
            fields.push_back(token);
        }

        if (fields.size() < 8) {
            throw std::runtime_error("Too few fields: " + std::to_string(fields.size()));
        }

        TraceRecord rec;

        // Field 0: DYN_ID
        rec.dyn_id = std::stoull(fields[0]);

        // Field 1: PC (hex string "0x...")
        rec.pc = std::stoull(fields[1], nullptr, 16);

        // Field 2: OPCODE
        rec.opcode = fields[2];
        // Normalize opcode to uppercase
        std::transform(rec.opcode.begin(), rec.opcode.end(),
                       rec.opcode.begin(), ::toupper);

        // Field 3: SRC_REGS (comma-separated, or "-")
        rec.src_regs = parseRegList(fields[3]);

        // Field 4: DST_REGS
        rec.dst_regs = parseRegList(fields[4]);

        // Field 5: MEM_READ flag
        rec.mem_read = (fields[5] == "1");

        // Field 6: MEM_WRITE flag
        rec.mem_write = (fields[6] == "1");

        // Field 7: THREAD_ID
        rec.thread_id = static_cast<uint32_t>(std::stoul(fields[7]));

        // Fields 8+: optional memory addresses
        rec.mem_read_addr = 0;
        rec.mem_write_addr = 0;
        rec.mem_read_size = 0;
        rec.mem_write_size = 0;

        for (size_t i = 8; i < fields.size(); ++i) {
            const std::string& f = fields[i];
            if (f.size() > 2 && f[0] == 'R' && f[1] == ':') {
                // R:0xADDR:SIZE
                parseMemField(f.substr(2), rec.mem_read_addr, rec.mem_read_size);
            } else if (f.size() > 2 && f[0] == 'W' && f[1] == ':') {
                parseMemField(f.substr(2), rec.mem_write_addr, rec.mem_write_size);
            }
        }

        return rec;
    }

    static void parseMemField(const std::string& s,
                               uint64_t& addr, uint32_t& size) {
        // Format: 0xADDR:SIZE
        auto colon = s.rfind(':');
        if (colon == std::string::npos) return;
        addr = std::stoull(s.substr(0, colon), nullptr, 16);
        size = static_cast<uint32_t>(std::stoul(s.substr(colon + 1)));
    }

    // Parse register list "rax,rbx,rcx" or "-"
    static std::vector<RegName> parseRegList(const std::string& s) {
        std::vector<RegName> regs;
        if (s == "-" || s.empty()) return regs;

        std::stringstream ss(s);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            if (tok.empty()) continue;
            // Lowercase
            std::transform(tok.begin(), tok.end(), tok.begin(), ::tolower);
            // Normalize to canonical name
            auto it = REG_NORMALIZE.find(tok);
            if (it != REG_NORMALIZE.end()) {
                regs.push_back(it->second);
            } else {
                regs.push_back(tok);  // keep unknown regs as-is
            }
        }
        return regs;
    }

    // Derive instruction category and branch flags from opcode
    static void categorize(TraceRecord& rec) {
        const std::string& op = rec.opcode;

        // Branch detection
        if (op == "JMP" || op == "JMPQ" ||
            op.size() > 0 && op[0] == 'J') {
            rec.is_branch = true;
            rec.category = TraceRecord::Category::BRANCH;
            return;
        }
        if (op == "CALL" || op == "CALLQ") {
            rec.is_call = true;
            rec.category = TraceRecord::Category::BRANCH;
            return;
        }
        if (op == "RET" || op == "RETQ" || op == "RETN") {
            rec.is_ret = true;
            rec.category = TraceRecord::Category::BRANCH;
            return;
        }

        // Arithmetic
        static const std::vector<std::string> arith = {
            "ADD","SUB","MUL","IMUL","DIV","IDIV","INC","DEC","NEG","ADC","SBB"
        };
        for (auto& a : arith) if (op == a) {
            rec.category = TraceRecord::Category::ARITHMETIC; return;
        }

        // Logic
        static const std::vector<std::string> logic = {
            "AND","OR","XOR","NOT","SHL","SHR","SAR","ROL","ROR","RCL","RCR",
            "SHLD","SHRD","BSF","BSR","BT","BTS","BTR","BTC"
        };
        for (auto& a : logic) if (op == a) {
            rec.category = TraceRecord::Category::LOGIC; return;
        }

        // Compare
        if (op == "CMP" || op == "TEST") {
            rec.category = TraceRecord::Category::COMPARE; return;
        }

        // Move
        static const std::vector<std::string> move = {
            "MOV","MOVSX","MOVZX","MOVSXD","MOVABS","LEA","XCHG","PUSH","POP",
            "PUSHF","POPF","PUSHFQ","POPFQ","LAHF","SAHF","MOVBE","BSWAP"
        };
        for (auto& a : move) if (op == a) {
            rec.category = TraceRecord::Category::MOVE; return;
        }

        // Float
        if (op.size() >= 1 && op[0] == 'F') {
            rec.category = TraceRecord::Category::FLOAT; return;
        }

        // SIMD
        if (op.size() >= 1 && (op[0] == 'V' || op.find("SSE") != std::string::npos
            || op.find("XMM") != std::string::npos)) {
            rec.category = TraceRecord::Category::SIMD; return;
        }

        rec.category = TraceRecord::Category::OTHER;
    }
};

#endif // ILP_TRACE_PARSER_HPP
