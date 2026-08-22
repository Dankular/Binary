#include "compass/core/il/high_level_il.hpp"

#include <sstream>

namespace compass::core::il {

namespace {

void indent(std::ostringstream& os, int depth) {
    for (int i = 0; i < depth; ++i) os << "    ";
}

void renderBody(const HLILBody& body, std::ostringstream& os, int depth);

void renderStatement(const HLILStatement& s, std::ostringstream& os, int depth) {
    indent(os, depth);
    switch (s.kind) {
        case HLILStatementKind::Expr:
            if (s.expr) os << render(*s.expr);
            os << "\n";
            return;
        case HLILStatementKind::Return:
            os << "return\n";
            return;
        case HLILStatementKind::Goto:
            os << "goto 0x" << std::hex << s.target << std::dec << "\n";
            return;
        case HLILStatementKind::Label:
            os << "label_0x" << std::hex << s.target << std::dec << ":\n";
            return;
        case HLILStatementKind::If:
            os << "if (" << (s.expr ? render(*s.expr) : "?") << ") {\n";
            renderBody(s.thenBody, os, depth + 1);
            indent(os, depth);
            if (s.elseBody.empty()) {
                os << "}\n";
            } else {
                os << "} else {\n";
                renderBody(s.elseBody, os, depth + 1);
                indent(os, depth);
                os << "}\n";
            }
            return;
        case HLILStatementKind::While:
            os << "while (" << (s.expr ? render(*s.expr) : "?") << ") {\n";
            renderBody(s.body, os, depth + 1);
            indent(os, depth);
            os << "}\n";
            return;
    }
}

void renderBody(const HLILBody& body, std::ostringstream& os, int depth) {
    for (auto& s : body) renderStatement(s, os, depth);
}

} // namespace

std::string render(const HLILFunction& fn) {
    std::ostringstream os;
    renderBody(fn.statements, os, 0);
    return os.str();
}

} // namespace compass::core::il
