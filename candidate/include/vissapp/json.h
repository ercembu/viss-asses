#pragma once
// VISS — RAII wrapper over the vendored cJSON parser. PROVIDED CODE.
//
// You do not need to change this. It exists so that the exercise is about
// the catalog schema, not about cJSON lifetime management.

#include <filesystem>
#include <string>

#include "cJSON.h"

namespace vissapp {

class JsonDoc {
public:
    JsonDoc() = default;
    ~JsonDoc();

    JsonDoc(JsonDoc&& other) noexcept;
    JsonDoc& operator=(JsonDoc&& other) noexcept;
    JsonDoc(const JsonDoc&)            = delete;
    JsonDoc& operator=(const JsonDoc&) = delete;

    // Read and parse a JSON file. Throws VissappError if the file is missing,
    // unreadable, or is not valid JSON.
    static JsonDoc ParseFile(const std::filesystem::path& path);

    // Parse JSON held in memory. Throws VissappError on a parse error.
    static JsonDoc ParseString(const std::string& text);

    const cJSON* root() const { return root_; }
    bool valid() const { return root_ != nullptr; }

private:
    explicit JsonDoc(cJSON* root) : root_(root) {}
    cJSON* root_ = nullptr;
};

} // namespace vissapp
