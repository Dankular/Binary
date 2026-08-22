#include "compass/core/type.hpp"

#include <sstream>

namespace compass::core {

std::string render(const Type& t) {
    switch (t.kind) {
        case TypeKind::Void: return "void";
        case TypeKind::Bool: return "bool";
        case TypeKind::Int: {
            std::ostringstream os;
            os << (t.isSigned ? "int" : "uint") << (t.width * 8) << "_t";
            return os.str();
        }
        case TypeKind::Float: return t.width == 4 ? "float" : "double";
        case TypeKind::Pointer:
            return (t.elementType ? render(*t.elementType) : "void") + " *";
        case TypeKind::Array: {
            std::ostringstream os;
            os << (t.elementType ? render(*t.elementType) : "void") << "[" << t.arrayLength << "]";
            return os.str();
        }
        case TypeKind::Struct:
        case TypeKind::Union: {
            std::string kw = t.kind == TypeKind::Struct ? "struct" : "union";
            return t.name.empty() ? kw + " { ... }" : kw + " " + t.name;
        }
        case TypeKind::Function: {
            std::ostringstream os;
            os << (t.elementType ? render(*t.elementType) : "void") << " " << t.name << "(";
            for (std::size_t i = 0; i < t.fields.size(); ++i) {
                if (i) os << ", ";
                os << (t.fields[i].type ? render(*t.fields[i].type) : "void");
            }
            os << ")";
            return os.str();
        }
        case TypeKind::Named:
            return t.name;
    }
    return "?";
}

} // namespace compass::core
