// VISS — RAII wrapper over the vendored cJSON parser. PROVIDED CODE.

#include "vissapp/json.h"

#include <utility>

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"

namespace vissapp {

JsonDoc::~JsonDoc()
{
    if (root_) cJSON_Delete(root_);
}

JsonDoc::JsonDoc(JsonDoc&& other) noexcept : root_(other.root_)
{
    other.root_ = nullptr;
}

JsonDoc& JsonDoc::operator=(JsonDoc&& other) noexcept
{
    if (this != &other) {
        if (root_) cJSON_Delete(root_);
        root_       = other.root_;
        other.root_ = nullptr;
    }
    return *this;
}

JsonDoc JsonDoc::ParseString(const std::string& text)
{
    cJSON* root = cJSON_Parse(text.c_str());
    if (!root) throw VissappError("invalid JSON");
    return JsonDoc(root);
}

JsonDoc JsonDoc::ParseFile(const std::filesystem::path& path)
{
    const std::string text = ReadTextFile(path);
    cJSON* root = cJSON_Parse(text.c_str());
    if (!root) throw VissappError("invalid JSON in " + path.string());
    return JsonDoc(root);
}

} // namespace vissapp
