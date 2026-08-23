// rz-ghidra p-code -> Compass MLIL translation (docs/DECOMPILER.md's
// deferred "p-code → MLIL translation" item). Everything in this file is
// grounded in `pdgx`'s actual XML output, inspected directly against real
// compiled fixtures while building this (not the pdgj-annotations idea
// floated in an earlier draft — pdgj's `annotations` array only carries
// rendered-text spans, address, and variable identity, not real p-code
// operations; `pdgx` is the command that actually exposes Ghidra's p-code
// AST, and its opcode numbers were cross-checked directly against
// Ghidra's own vendored opcodes.hh, not guessed from memory):
//
//   rizin -q -c 'aa; pdgx @ sym.add' sample.o
//
// gives (trimmed):
//   <result><function><function name="sym.add" size="30">
//     <localdb>...<symbollist><mapsym><symbol name="param_1" .../>
//       <addr space="register" offset="0x38"/>...</mapsym>...</symbollist></localdb>
//     <ast><varnodes>
//         <addr space="register" offset="0x38" size="4" ref="0x9c" input="true"/>...
//       </varnodes>
//       <block index="0"><rangelist><range .../></rangelist>
//         <op code="19"><seqnum offset="0x8000054" .../>
//           <addr ref="0x34"/><addr ref="0x9d"/><addr ref="0x9c"/></op>
//         ...
//       </block>
//       <blockedge index="1"><edge end="0" rev="1"/></blockedge>...
//     </ast>
//     <highlist><high repref="0xda" class="param" symref="0x400...004">
//       <type .../><addr ref="0xda"/></high>...</highlist>
//   </function></function><code>...</code></result>
//
// The translation strategy this drove:
//  - `<op code="N">`'s first child is the *output* varnode (`<addr>`) if
//    the op produces one, or a `<void/>` marker if it doesn't — the same
//    discriminator LOAD/STORE/BRANCH/CALL/RETURN/CBRANCH all use.
//  - A varnode's *name* comes from `<highlist>`: each `<high>` groups every
//    p-code SSA version of one logical variable under one `repref`, with a
//    `symref` into `<localdb>`'s symbol table when Ghidra bound it to a
//    real named local/parameter (confirmed directly: `var_ch`'s `<high>`
//    lists 5 different varnode refs — one per SSA version across the
//    function — as members). No `symref` means an anonymous SSA temp;
//    those get a synthetic `t_<repref>` name instead of inventing one.
//  - Because Compass's plain (non-SSA) MLIL already allows one variable
//    name to be reassigned many times, and Ghidra's HighVariable grouping
//    already unifies every SSA version of one logical variable under one
//    name, a MULTIEQUAL (phi, code 60) whose output and every input share
//    that same resolved name is already fully represented by ordinary
//    reassignment — verified directly against `max3_test`'s two real phi
//    merges (v_ch/m and its comparison chain) before trusting this. A
//    MULTIEQUAL that *doesn't* satisfy that (Ghidra's grouping genuinely
//    diverged) falls back to Unimplemented rather than emitting something
//    that could be silently wrong.
//  - Every opcode this file doesn't have a confident MLILOp for (float
//    ops, PIECE/SUBPIECE/CAST, indirect calls, flag-test ops with no MLIL
//    equivalent) becomes an Unimplemented expression carrying Ghidra's own
//    opcode name and whatever operands were available — the same
//    never-silently-misrepresent fallback llil_lifter.cpp already uses for
//    ESIL tokens it doesn't recognize.

#include "compass/core/il/pcode_translator.hpp"

#include <expat.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace compass::core::il {

namespace {

// ---------------------------------------------------------------------
// A minimal XML DOM, built once via expat's SAX callbacks. pdgx's schema
// is simple enough (no mixed content this translation cares about, no
// namespaces) that a full DOM library would be overkill; expat itself is
// already a standard system dependency (libexpat1-dev), not a new one.
// ---------------------------------------------------------------------

struct XmlNode {
    std::string tag;
    std::unordered_map<std::string, std::string> attrs;
    std::vector<XmlNode> children;

    const std::string& attr(const std::string& name) const {
        static const std::string empty;
        auto it = attrs.find(name);
        return it != attrs.end() ? it->second : empty;
    }
    bool hasAttr(const std::string& name) const { return attrs.count(name) != 0; }
};

struct XmlParseState {
    std::vector<XmlNode> stack;
    XmlNode root;
    bool haveRoot = false;
};

void XMLCALL onStart(void* userData, const XML_Char* name, const XML_Char** atts) {
    auto* st = static_cast<XmlParseState*>(userData);
    XmlNode node;
    node.tag = name;
    for (int i = 0; atts[i]; i += 2) node.attrs[atts[i]] = atts[i + 1];
    st->stack.push_back(std::move(node));
}

void XMLCALL onEnd(void* userData, const XML_Char*) {
    auto* st = static_cast<XmlParseState*>(userData);
    XmlNode node = std::move(st->stack.back());
    st->stack.pop_back();
    if (st->stack.empty()) {
        st->root = std::move(node);
        st->haveRoot = true;
    } else {
        st->stack.back().children.push_back(std::move(node));
    }
}

std::optional<XmlNode> parseXml(const std::string& xml) {
    XML_Parser parser = XML_ParserCreate(nullptr);
    XmlParseState state;
    XML_SetUserData(parser, &state);
    XML_SetElementHandler(parser, onStart, onEnd);
    auto status = XML_Parse(parser, xml.data(), static_cast<int>(xml.size()), 1);
    bool ok = status != XML_STATUS_ERROR && state.haveRoot;
    XML_ParserFree(parser);
    if (!ok) return std::nullopt;
    return state.root;
}

/// First descendant (any depth) with this tag, or nullptr — used instead
/// of hardcoding exact nesting depth, since pdgx wraps the actual AST in
/// `<result><function><function name=...>` (an outer generic wrapper
/// around the real per-function element) and this translation only cares
/// about finding `<ast>`/`<localdb>`/`<highlist>` wherever they land, not
/// about replicating that wrapper structure.
const XmlNode* findDescendant(const XmlNode& n, const std::string& tag) {
    for (auto& c : n.children) {
        if (c.tag == tag) return &c;
        if (auto* r = findDescendant(c, tag)) return r;
    }
    return nullptr;
}

void collectDescendants(const XmlNode& n, const std::string& tag, std::vector<const XmlNode*>& out) {
    for (auto& c : n.children) {
        if (c.tag == tag) out.push_back(&c);
        collectDescendants(c, tag, out);
    }
}

const XmlNode* findChild(const XmlNode& n, const std::string& tag) {
    for (auto& c : n.children) {
        if (c.tag == tag) return &c;
    }
    return nullptr;
}

/// Handles both "0x..." hex (offsets, addresses) and plain decimal (sizes,
/// opcodes, block indices) — every numeric attribute pdgx emits is one or
/// the other, never octal, so base 0's auto-detection is unambiguous here.
std::uint64_t parseNum(const std::string& s) {
    if (s.empty()) return 0;
    return std::strtoull(s.c_str(), nullptr, 0);
}

// ---------------------------------------------------------------------
// Ghidra's own p-code opcode table — cross-checked directly against
// opcodes.hh/opcodes.cc in the vendored Ghidra decompiler source (the
// same one rz-ghidra compiles, per docs/DECOMPILER.md), not recalled from
// memory. Only the codes this translator actually treats specially are
// named; opName() below covers the rest for Unimplemented's text.
// ---------------------------------------------------------------------

enum GhidraOp : int {
    OP_COPY = 1,
    OP_LOAD = 2,
    OP_STORE = 3,
    OP_BRANCH = 4,
    OP_CBRANCH = 5,
    OP_BRANCHIND = 6,
    OP_CALL = 7,
    OP_CALLIND = 8,
    OP_CALLOTHER = 9,
    OP_RETURN = 10,
    OP_INT_EQUAL = 11,
    OP_INT_NOTEQUAL = 12,
    OP_INT_SLESS = 13,
    OP_INT_SLESSEQUAL = 14,
    OP_INT_LESS = 15,
    OP_INT_LESSEQUAL = 16,
    OP_INT_ZEXT = 17,
    OP_INT_SEXT = 18,
    OP_INT_ADD = 19,
    OP_INT_SUB = 20,
    OP_INT_CARRY = 21,
    OP_INT_SCARRY = 22,
    OP_INT_SBORROW = 23,
    OP_INT_2COMP = 24,
    OP_INT_NEGATE = 25,
    OP_INT_XOR = 26,
    OP_INT_AND = 27,
    OP_INT_OR = 28,
    OP_INT_LEFT = 29,
    OP_INT_RIGHT = 30,
    OP_INT_SRIGHT = 31,
    OP_INT_MULT = 32,
    OP_INT_DIV = 33,
    OP_INT_SDIV = 34,
    OP_INT_REM = 35,
    OP_INT_SREM = 36,
    OP_BOOL_NEGATE = 37,
    OP_BOOL_XOR = 38,
    OP_BOOL_AND = 39,
    OP_BOOL_OR = 40,
    OP_MULTIEQUAL = 60,
    OP_PTRADD = 65,
};

/// Ghidra's own opcode name table (opcodes.cc's opcode_names[]) — used
/// verbatim for Unimplemented's `.text` so an unhandled op is always
/// labeled with Ghidra's real name, never a made-up one.
const char* opName(int code) {
    static const char* names[] = {
        "BLANK",    "COPY",         "LOAD",       "STORE",         "BRANCH",     "CBRANCH",
        "BRANCHIND", "CALL",        "CALLIND",    "CALLOTHER",     "RETURN",     "INT_EQUAL",
        "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_ZEXT",
        "INT_SEXT", "INT_ADD",      "INT_SUB",    "INT_CARRY",     "INT_SCARRY", "INT_SBORROW",
        "INT_2COMP", "INT_NEGATE",  "INT_XOR",    "INT_AND",       "INT_OR",     "INT_LEFT",
        "INT_RIGHT", "INT_SRIGHT",  "INT_MULT",   "INT_DIV",       "INT_SDIV",   "INT_REM",
        "INT_SREM", "BOOL_NEGATE",  "BOOL_XOR",   "BOOL_AND",      "BOOL_OR",    "FLOAT_EQUAL",
        "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "UNUSED1", "FLOAT_NAN", "FLOAT_ADD",
        "FLOAT_DIV", "FLOAT_MULT",  "FLOAT_SUB",  "FLOAT_NEG",     "FLOAT_ABS",  "FLOAT_SQRT",
        "INT2FLOAT", "FLOAT2FLOAT", "TRUNC",      "CEIL",          "FLOOR",      "ROUND",
        "MULTIEQUAL", "INDIRECT",   "PIECE",      "SUBPIECE",      "CAST",       "PTRADD",
        "PTRSUB",   "SEGMENTOP",    "CPOOLREF",   "NEW",           "INSERT",     "EXTRACT",
        "POPCOUNT", "LZCOUNT",
    };
    if (code >= 0 && static_cast<std::size_t>(code) < sizeof(names) / sizeof(names[0])) {
        return names[code];
    }
    return "UNKNOWN_OP";
}

// ---------------------------------------------------------------------
// Parsed p-code domain model
// ---------------------------------------------------------------------

struct VarnodeInfo {
    std::string space;
    std::uint64_t offset = 0; // for space=="const", this IS the value
    std::uint32_t size = 0;
};

struct SymbolInfo {
    std::string name;
};

/// One `<high>` element: the group of varnode refs Ghidra considers SSA
/// versions of the same logical variable, and (if symbol-bound) which
/// localdb symbol names it.
struct HighInfo {
    std::string repref;
    std::optional<std::string> symref;
};

struct OpInfo {
    int code = 0;
    Address address = 0;
    bool hasOutput = false;
    std::string outputRef;
    std::vector<std::string> inputRefs; // addr-typed operands only, in order; spaceid markers dropped
};

struct BlockInfo {
    int index = 0;
    Address start = 0;
    Address end = 0;
    std::vector<OpInfo> ops;
};

struct ParsedFunction {
    std::unordered_map<std::string, VarnodeInfo> varnodes;      // ref -> info
    std::unordered_map<std::string, SymbolInfo> symbolById;     // localdb symbol id -> info
    std::unordered_map<std::string, HighInfo> highByMemberRef;  // varnode ref -> owning <high>
    std::vector<BlockInfo> blocks;                               // in <block index> order
    std::map<int, std::vector<int>> predecessors;                // block index -> predecessor indices
};

/// Parses everything this translator needs out of one function's pdgx
/// XML. Returns std::nullopt only when the document has no `<ast>` at
/// all (rz-ghidra failed to decompile this function) — a block or op this
/// parser doesn't recognize is simply skipped, not a hard failure, so a
/// partially-unfamiliar function still translates as much as it can.
std::optional<ParsedFunction> parseFunction(const XmlNode& root) {
    const XmlNode* ast = findDescendant(root, "ast");
    if (!ast) return std::nullopt;

    ParsedFunction pf;

    // <localdb> ... <mapsym><symbol id=... name=.../><addr .../></mapsym> ...
    // Symbol id -> name only; storage location comes from the varnode's
    // own space/offset when we resolve a reference, not from here.
    if (const XmlNode* localdb = findDescendant(root, "localdb")) {
        std::vector<const XmlNode*> mapsyms;
        collectDescendants(*localdb, "mapsym", mapsyms);
        for (auto* mapsym : mapsyms) {
            const XmlNode* symbol = findChild(*mapsym, "symbol");
            if (!symbol || !symbol->hasAttr("id") || !symbol->hasAttr("name")) continue;
            pf.symbolById[symbol->attr("id")] = SymbolInfo{symbol->attr("name")};
        }
    }

    // <highlist><high repref=... symref=(optional)><type/><addr ref=.../>...</high>...
    if (const XmlNode* highlist = findDescendant(root, "highlist")) {
        for (auto& high : highlist->children) {
            if (high.tag != "high") continue;
            HighInfo info;
            info.repref = high.attr("repref");
            if (high.hasAttr("symref")) info.symref = high.attr("symref");
            for (auto& member : high.children) {
                if (member.tag == "addr" && member.hasAttr("ref")) {
                    pf.highByMemberRef[member.attr("ref")] = info;
                }
            }
        }
    }

    // <ast><varnodes><addr space=... offset=... size=... ref=.../>...</varnodes>
    if (const XmlNode* varnodes = findChild(*ast, "varnodes")) {
        for (auto& v : varnodes->children) {
            if (v.tag != "addr" || !v.hasAttr("ref")) continue;
            VarnodeInfo info;
            info.space = v.attr("space");
            info.offset = parseNum(v.attr("offset"));
            info.size = static_cast<std::uint32_t>(parseNum(v.attr("size")));
            pf.varnodes[v.attr("ref")] = info;
        }
    }

    // <ast><block index=...><rangelist><range first=... last=.../></rangelist>
    //   <op code=...><seqnum offset=.../> <void/>|<addr ref=.../> ...operands</op>...
    // </block>...
    for (auto& child : ast->children) {
        if (child.tag != "block") continue;
        BlockInfo block;
        block.index = static_cast<int>(parseNum(child.attr("index")));
        if (const XmlNode* rangelist = findChild(child, "rangelist")) {
            if (const XmlNode* range = findChild(*rangelist, "range")) {
                block.start = parseNum(range->attr("first"));
                block.end = parseNum(range->attr("last"));
            }
        }
        for (auto& opNode : child.children) {
            if (opNode.tag != "op") continue;
            OpInfo op;
            op.code = static_cast<int>(parseNum(opNode.attr("code")));
            if (const XmlNode* seqnum = findChild(opNode, "seqnum")) {
                op.address = parseNum(seqnum->attr("offset"));
            }
            bool first = true;
            for (auto& operand : opNode.children) {
                if (operand.tag == "seqnum") continue;
                if (operand.tag == "void") {
                    first = false;
                    continue;
                }
                if (operand.tag == "spaceid") continue; // LOAD/STORE's address-space marker — not a value
                if (operand.tag != "addr" || !operand.hasAttr("ref")) continue;
                if (first) {
                    op.hasOutput = true;
                    op.outputRef = operand.attr("ref");
                } else {
                    op.inputRefs.push_back(operand.attr("ref"));
                }
                first = false;
            }
            block.ops.push_back(std::move(op));
        }
        pf.blocks.push_back(std::move(block));
    }

    // <ast><blockedge index=N><edge end=M .../>...</blockedge>...
    // Lists, per block N, which blocks M are its *predecessors* — inverted
    // below (in translatePcode) into each block's successors.
    for (auto& child : ast->children) {
        if (child.tag != "blockedge") continue;
        int idx = static_cast<int>(parseNum(child.attr("index")));
        for (auto& edge : child.children) {
            if (edge.tag != "edge") continue;
            pf.predecessors[idx].push_back(static_cast<int>(parseNum(edge.attr("end"))));
        }
    }

    return pf;
}

// ---------------------------------------------------------------------
// p-code -> MLIL translation
// ---------------------------------------------------------------------

class Translator {
public:
    explicit Translator(const ParsedFunction& pf) : pf_(pf) {}

    /// Resolves a varnode ref to the MLILVar it should read/write as —
    /// symbol-bound name when highlist/localdb gives us one, a synthetic
    /// name otherwise. Same resolution regardless of read or write side,
    /// since Compass's plain MLIL (unlike SSA) reuses one Var identity for
    /// every access of the same logical variable.
    MLILVar resolveVar(const std::string& ref) const {
        auto vit = pf_.varnodes.find(ref);
        VarnodeInfo vinfo = vit != pf_.varnodes.end() ? vit->second : VarnodeInfo{};

        MLILVarKind kind = MLILVarKind::Temp;
        if (vinfo.space == "register") kind = MLILVarKind::Register;
        else if (vinfo.space == "stack") kind = MLILVarKind::Stack;
        // "unique" (Ghidra's own SSA-temp space), or anything else
        // unrecognized, stays Temp — genuinely no physical storage.

        std::string name;
        auto hit = pf_.highByMemberRef.find(ref);
        if (hit != pf_.highByMemberRef.end() && hit->second.symref) {
            auto sit = pf_.symbolById.find(*hit->second.symref);
            if (sit != pf_.symbolById.end()) name = sit->second.name;
        }
        if (name.empty()) {
            // No symbol binding — synthesize a name from the *high group*
            // (hit->second.repref) when one exists, so every SSA version
            // of the same anonymous temp shares one name, same as a named
            // variable would; fall back to the raw varnode ref only when
            // this varnode has no high entry at all.
            std::string key = (hit != pf_.highByMemberRef.end()) ? hit->second.repref : ref;
            if (kind == MLILVarKind::Register) {
                name = "reg_" + stripHexPrefix(key);
            } else if (kind == MLILVarKind::Stack) {
                name = "stack_" + stripHexPrefix(key);
            } else {
                name = "t_" + stripHexPrefix(key);
            }
        }

        MLILVar v;
        v.kind = kind;
        v.name = name;
        v.widthHint = vinfo.size;
        return v;
    }

    /// Builds a read expression for a varnode ref: a literal Const for
    /// const-space, a Var read (via resolveVar) for everything else.
    MLILExprPtr exprFor(const std::string& ref) const {
        auto vit = pf_.varnodes.find(ref);
        if (vit != pf_.varnodes.end() && vit->second.space == "const") {
            auto e = MLILExpr::make(MLILOp::Const);
            e->constValue = vit->second.offset;
            return e;
        }
        auto e = MLILExpr::make(MLILOp::Var);
        e->var = resolveVar(ref);
        return e;
    }

    Address addressOf(const std::string& ref) const {
        auto vit = pf_.varnodes.find(ref);
        return vit != pf_.varnodes.end() ? vit->second.offset : 0;
    }

    std::uint32_t sizeOf(const std::string& ref) const {
        auto vit = pf_.varnodes.find(ref);
        return vit != pf_.varnodes.end() ? vit->second.size : 0;
    }

    /// Wraps `body` as `SetVar(outputVar, body)` if `op` produced an
    /// output, otherwise returns `body` as its own top-level statement.
    MLILExprPtr maybeAssign(const OpInfo& op, MLILExprPtr body) const {
        if (!op.hasOutput) return body;
        auto set = MLILExpr::make(MLILOp::SetVar);
        set->var = resolveVar(op.outputRef);
        set->operands = {std::move(body)};
        return set;
    }

    /// Generic fallback for any opcode without a specific MLILOp — real
    /// Ghidra opcode name, every available input attached, never silently
    /// dropped or misrepresented.
    MLILExprPtr unimplemented(const OpInfo& op) const {
        auto e = MLILExpr::make(MLILOp::Unimplemented);
        e->text = opName(op.code);
        for (auto& in : op.inputRefs) e->operands.push_back(exprFor(in));
        return maybeAssign(op, e);
    }

    MLILExprPtr binOp(const OpInfo& op, MLILOp mop) const {
        auto e = MLILExpr::make(mop);
        if (op.inputRefs.size() >= 2) {
            e->operands = {exprFor(op.inputRefs[0]), exprFor(op.inputRefs[1])};
        }
        return maybeAssign(op, e);
    }

    /// Translates one op to zero or one MLIL statements. Returns nullptr
    /// for ops that legitimately produce nothing (MULTIEQUAL folded away
    /// by shared naming — see the file header comment).
    MLILExprPtr translateOp(const OpInfo& op, const BlockInfo& block) {
        switch (op.code) {
            case OP_COPY:
                return op.inputRefs.empty() ? nullptr : maybeAssign(op, exprFor(op.inputRefs[0]));

            case OP_LOAD: {
                if (op.inputRefs.empty()) return nullptr;
                auto load = MLILExpr::make(MLILOp::Load);
                load->operands = {exprFor(op.inputRefs.back())}; // pointer (spaceid already dropped)
                load->constValue = op.hasOutput ? sizeOf(op.outputRef) : 0;
                return maybeAssign(op, load);
            }
            case OP_STORE: {
                if (op.inputRefs.size() < 2) return nullptr;
                auto store = MLILExpr::make(MLILOp::Store);
                auto& pointerRef = op.inputRefs[op.inputRefs.size() - 2];
                auto& valueRef = op.inputRefs.back();
                store->operands = {exprFor(pointerRef), exprFor(valueRef)};
                store->constValue = sizeOf(valueRef);
                return store; // void op — no output to assign
            }

            case OP_BRANCH: {
                if (op.inputRefs.empty()) return nullptr;
                auto e = MLILExpr::make(MLILOp::Goto);
                e->trueTarget = addressOf(op.inputRefs[0]);
                return e;
            }
            case OP_CBRANCH: {
                if (op.inputRefs.size() < 2) return nullptr;
                Address target = addressOf(op.inputRefs[0]);
                Address fallthrough = otherSuccessor(block, target);
                auto e = MLILExpr::make(MLILOp::If);
                e->operands = {exprFor(op.inputRefs[1])};
                e->trueTarget = target;
                e->falseTarget = fallthrough;
                return e;
            }
            case OP_BRANCHIND:
                return unimplemented(op);

            case OP_CALL: {
                if (op.inputRefs.empty()) return nullptr;
                auto call = MLILExpr::make(MLILOp::Call);
                auto target = MLILExpr::make(MLILOp::Const);
                target->constValue = addressOf(op.inputRefs[0]);
                call->operands.push_back(target);
                for (std::size_t i = 1; i < op.inputRefs.size(); ++i) {
                    call->operands.push_back(exprFor(op.inputRefs[i]));
                }
                return maybeAssign(op, call);
            }
            case OP_CALLIND:
            case OP_CALLOTHER:
                return unimplemented(op);

            case OP_RETURN: {
                auto e = MLILExpr::make(MLILOp::Ret);
                // inputRefs[0] is the return-address placeholder Ghidra's
                // p-code always attaches to RETURN, not a real value —
                // verified directly (it's a const 0 in every fixture); the
                // real return value, when the decompiler actually
                // propagated one this far, is inputRefs[1].
                if (op.inputRefs.size() > 1) e->operands = {exprFor(op.inputRefs[1])};
                return e;
            }

            case OP_INT_EQUAL:
            case OP_INT_NOTEQUAL:
            case OP_INT_SLESS:
            case OP_INT_SLESSEQUAL:
            case OP_INT_LESS:
            case OP_INT_LESSEQUAL:
                return binOp(op, MLILOp::Cmp);

            case OP_INT_ZEXT:
            case OP_INT_SEXT:
                return unimplemented(op);

            case OP_INT_ADD: return binOp(op, MLILOp::Add);
            case OP_INT_SUB: return binOp(op, MLILOp::Sub);
            case OP_INT_CARRY:
            case OP_INT_SCARRY:
            case OP_INT_SBORROW:
            case OP_INT_2COMP:
            case OP_INT_NEGATE:
                return unimplemented(op);
            case OP_INT_XOR: return binOp(op, MLILOp::Xor);
            case OP_INT_AND: return binOp(op, MLILOp::And);
            case OP_INT_OR: return binOp(op, MLILOp::Or);
            case OP_INT_LEFT: return binOp(op, MLILOp::Shl);
            case OP_INT_RIGHT: return binOp(op, MLILOp::Shr);
            case OP_INT_SRIGHT: return binOp(op, MLILOp::Sar);
            case OP_INT_MULT: return binOp(op, MLILOp::Mul);
            case OP_INT_DIV: return binOp(op, MLILOp::Div);
            case OP_INT_SDIV: return binOp(op, MLILOp::SDiv);
            case OP_INT_REM: return binOp(op, MLILOp::Mod);
            case OP_INT_SREM: return binOp(op, MLILOp::SMod);

            case OP_BOOL_NEGATE:
                return unimplemented(op);
            case OP_BOOL_XOR: return binOp(op, MLILOp::Xor);
            case OP_BOOL_AND: return binOp(op, MLILOp::And);
            case OP_BOOL_OR: return binOp(op, MLILOp::Or);

            case OP_MULTIEQUAL: {
                if (!op.hasOutput) return unimplemented(op);
                std::string outName = resolveVar(op.outputRef).name;
                bool allSameName = true;
                for (auto& in : op.inputRefs) {
                    if (resolveVar(in).name != outName) {
                        allSameName = false;
                        break;
                    }
                }
                // Every input and the output are the same logical
                // variable (Ghidra's own HighVariable grouping already
                // unified them) — already fully represented by ordinary
                // reassignment under Compass's plain-MLIL model, so this
                // phi is a genuine no-op here, not lost information. See
                // the file header comment for how this was verified.
                if (allSameName) return nullptr;
                return unimplemented(op);
            }

            case OP_PTRADD: {
                // Verified directly against a real `arr[i]` fixture:
                // output = base + index * elementSize.
                if (op.inputRefs.size() < 3) return unimplemented(op);
                auto mul = MLILExpr::make(MLILOp::Mul);
                mul->operands = {exprFor(op.inputRefs[1]), exprFor(op.inputRefs[2])};
                auto add = MLILExpr::make(MLILOp::Add);
                add->operands = {exprFor(op.inputRefs[0]), mul};
                return maybeAssign(op, add);
            }

            default:
                return unimplemented(op);
        }
    }

private:
    static std::string stripHexPrefix(const std::string& s) {
        return (s.size() > 2 && s[0] == '0' && s[1] == 'x') ? s.substr(2) : s;
    }

    /// CBRANCH only tells us its taken target explicitly; the fallthrough
    /// target is "whichever of this block's successors isn't that one" —
    /// derived from the blockedge-inverted successor list built in
    /// translatePcode() and passed in via successors_.
    Address otherSuccessor(const BlockInfo& block, Address takenTarget) const {
        auto it = successors_.find(block.index);
        if (it == successors_.end()) return takenTarget;
        for (Address s : it->second) {
            if (s != takenTarget) return s;
        }
        return takenTarget; // only one successor known — defensive fallback, not expected in practice
    }

public:
    std::map<int, std::vector<Address>> successors_;

private:
    const ParsedFunction& pf_;
};

} // namespace

PcodeTranslationResult translatePcode(const std::string& pdgxXml, Address entry) {
    PcodeTranslationResult result;

    auto root = parseXml(pdgxXml);
    if (!root) {
        result.error = "pdgx produced no parseable XML — rz-ghidra may not be installed "
                        "(see scripts/build_rz_ghidra.sh)";
        return result;
    }

    auto pf = parseFunction(*root);
    if (!pf) {
        result.error = "pdgx's XML had no <ast> for this function";
        return result;
    }

    // Block index -> start address, needed both for MLILBasicBlock's own
    // identity and to turn blockedge's predecessor lists into successors.
    std::unordered_map<int, Address> blockAddr;
    for (auto& b : pf->blocks) blockAddr[b.index] = b.start;

    std::map<int, std::vector<Address>> successors;
    for (auto& [succIdx, preds] : pf->predecessors) {
        for (int predIdx : preds) {
            auto it = blockAddr.find(succIdx);
            if (it != blockAddr.end()) successors[predIdx].push_back(it->second);
        }
    }

    Translator translator(*pf);
    translator.successors_ = successors;

    MLILFunction mlil;
    mlil.entry = entry;

    for (auto& b : pf->blocks) {
        MLILBasicBlock bb;
        bb.start = b.start;
        bb.end = b.end;
        auto sit = successors.find(b.index);
        if (sit != successors.end()) bb.successors = sit->second;
        auto pit = pf->predecessors.find(b.index);
        if (pit != pf->predecessors.end()) {
            for (int predIdx : pit->second) {
                auto it = blockAddr.find(predIdx);
                if (it != blockAddr.end()) bb.predecessors.push_back(it->second);
            }
        }

        for (auto& op : b.ops) {
            auto expr = translator.translateOp(op, b);
            if (!expr) continue; // e.g. a folded-away MULTIEQUAL
            MLILInstruction instr;
            instr.address = op.address;
            instr.expressions = {expr};
            bb.instructions.push_back(std::move(instr));
        }

        mlil.basicBlocks.push_back(std::move(bb));
    }

    result.success = true;
    result.mlil = std::move(mlil);
    return result;
}

} // namespace compass::core::il
