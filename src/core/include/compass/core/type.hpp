#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace compass::core {

enum class TypeKind {
    Void,
    Bool,
    Int,     // width in bytes (typeWidth), signed via `isSigned`
    Float,   // width in bytes (4 or 8)
    Pointer, // pointee in `elementType`
    Array,   // element in `elementType`, length in `arrayLength`
    Struct,
    Union,
    Function, // return in `elementType`, params in `fields`' types (names ignored)
    Named,    // a reference to a type registered in a TypeLibrary by name
};

struct Type;
using TypePtr = std::shared_ptr<Type>;

struct StructField {
    std::string name;
    TypePtr type;
    std::uint64_t offset = 0; // byte offset within the struct/union
};

struct Type {
    TypeKind kind = TypeKind::Void;
    std::string name;          // struct/union/named-type/function name; empty for anonymous
    std::uint32_t width = 0;   // byte size for Int/Float/Pointer; 0 = unknown
    bool isSigned = false;     // meaningful for Int
    TypePtr elementType;       // Pointer/Array element, or Function return type
    std::uint64_t arrayLength = 0;
    std::vector<StructField> fields; // Struct/Union members, or Function parameters

    static TypePtr makeVoid() {
        auto t = std::make_shared<Type>();
        t->kind = TypeKind::Void;
        return t;
    }
    static TypePtr makeBool() {
        auto t = std::make_shared<Type>();
        t->kind = TypeKind::Bool;
        t->width = 1;
        return t;
    }
    static TypePtr makeInt(std::uint32_t widthBytes, bool isSigned, std::string name = "") {
        auto t = std::make_shared<Type>();
        t->kind = TypeKind::Int;
        t->width = widthBytes;
        t->isSigned = isSigned;
        t->name = std::move(name);
        return t;
    }
    static TypePtr makePointer(TypePtr pointee, std::uint32_t widthBytes = 8) {
        auto t = std::make_shared<Type>();
        t->kind = TypeKind::Pointer;
        t->width = widthBytes;
        t->elementType = std::move(pointee);
        return t;
    }
};

/// C-like rendering: `int32_t`, `struct Foo *`, `uint8_t[16]`, etc.
std::string render(const Type& t);

/// A named collection of types — the seed of what Binary Ninja calls a
/// "type library"/"type archive": struct/union/typedef definitions a
/// binary (or a whole project) shares. Just a registry today; import/
/// export and cross-binary sharing are future work (see docs/ROADMAP.md).
class TypeLibrary {
public:
    void define(const std::string& name, TypePtr type) { types_[name] = std::move(type); }
    TypePtr lookup(const std::string& name) const {
        auto it = types_.find(name);
        return it != types_.end() ? it->second : nullptr;
    }
    const std::unordered_map<std::string, TypePtr>& all() const { return types_; }

private:
    std::unordered_map<std::string, TypePtr> types_;
};

} // namespace compass::core
