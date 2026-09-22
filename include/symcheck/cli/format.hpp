#pragma once

#include "symcheck/diagnose/explain.hpp"
#include "symcheck/diagnose/match.hpp"
#include "symcheck/diagnose/project_find.hpp"
#include "symcheck/diagnose/project_tools.hpp"
#include "symcheck/diagnose/why.hpp"
#include "symcheck/graph/import_graph.hpp"
#include "symcheck/ir/binary.hpp"

#include <string>

namespace symcheck {

void print_inspect(const BinaryImage& image, bool json);
void print_exports(const BinaryImage& image, bool json);
void print_imports(const BinaryImage& image, bool json);
void print_symbol_lookup(const BinaryImage& image, const std::string& query,
                         const SymbolMatch& match, bool json);
void print_compare(const BinaryImage& a, const BinaryImage& b, bool json);
void print_explain(const ExplainReport& report, bool json);
void print_graph(const GraphNode& node);
void print_find(const FindReport& report, bool json);
void print_why(const WhyReport& report, bool json, bool verbose = false);
void print_deps(const DepNode& node, bool json);
void print_duplicates(const std::vector<DuplicateGroup>& groups, bool json);
void print_matrix(const std::vector<MatrixRow>& rows, bool json);

}  // namespace symcheck
