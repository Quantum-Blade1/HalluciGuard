"""
AST Parser — tree-sitter + Python ast wrappers for import extraction.

Supports Python and JavaScript source code. Uses Python's built-in ast module
with a fallback to tree-sitter, and tree-sitter for JS.
"""

from __future__ import annotations

import ast as python_ast
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ImportInfo:
    """Import information extracted from source code."""

    package_name: str
    module_name: str
    import_type: str
    language: str
    line_no: int

    # Backwards compatibility for the rest of the pipeline
    @property
    def line_number(self) -> int:
        return self.line_no


class ASTParser:
    """Multi-language AST parser for import extraction."""

    def __init__(self) -> None:
        self._py_parser = None
        self._js_parser = None
        self._py_language = None
        self._js_language = None
        self._ts_available = False
        self._init_tree_sitter()

    def _init_tree_sitter(self) -> None:
        """Initialize tree-sitter parsers for Python and JavaScript."""
        try:
            import tree_sitter_python as tspython
            import tree_sitter_javascript as tsjavascript
            from tree_sitter import Language, Parser

            self._py_language = Language(tspython.language())
            self._py_parser = Parser(self._py_language)

            self._js_language = Language(tsjavascript.language())
            self._js_parser = Parser(self._js_language)

            self._ts_available = True
            logger.info("tree-sitter initialized for Python + JavaScript")
        except (ImportError, TypeError) as e:
            logger.warning("tree-sitter not available: %s", e)
            self._ts_available = False

    def extract_imports(self, code: str, language: str = "python") -> list[ImportInfo]:
        """Dispatcher function to extract imports based on language."""
        if language == "python":
            return self._extract_python_imports(code)
        elif language == "javascript":
            return self._extract_javascript_imports(code)
        else:
            logger.warning("Unsupported language: %s", language)
            return []

    def _extract_python_imports(self, code: str) -> list[ImportInfo]:
        """Extract Python imports using stdlib ast, fallback to tree-sitter."""
        imports = self._extract_python_imports_ast(code)
        if not imports and self._ts_available and self._py_parser:
            # If ast failed (e.g. syntax error in fragment), fallback to tree-sitter
            try:
                # Let's verify if ast actually failed to parse or just found 0 imports
                python_ast.parse(code)
            except SyntaxError:
                imports = self._extract_python_imports_ts(code)
        return imports

    def _extract_python_imports_ast(self, code: str) -> list[ImportInfo]:
        """Extract Python imports via built-in ast module."""
        imports: list[ImportInfo] = []
        try:
            tree = python_ast.parse(code)
        except SyntaxError:
            return imports

        for node in python_ast.walk(tree):
            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    # Filter relative imports (though absolute ast.Import doesn't start with .)
                    if alias.name.startswith('.'):
                        continue
                        
                    imports.append(
                        ImportInfo(
                            package_name=alias.name.split('.')[0],
                            module_name=alias.name,
                            import_type="import",
                            language="python",
                            line_no=node.lineno,
                        )
                    )
            elif isinstance(node, python_ast.ImportFrom):
                if node.module and node.level == 0:  # level == 0 means absolute import
                    imports.append(
                        ImportInfo(
                            package_name=node.module.split('.')[0],
                            module_name=node.module,
                            import_type="from_import",
                            language="python",
                            line_no=node.lineno,
                        )
                    )

        return imports

    def _extract_python_imports_ts(self, code: str) -> list[ImportInfo]:
        """Extract Python imports via tree-sitter tree walking (fallback)."""
        tree = self._py_parser.parse(code.encode("utf-8"))
        imports: list[ImportInfo] = []

        for child in tree.root_node.children:
            if child.type == "import_statement":
                name_node = child.child_by_field_name("name")
                if name_node:
                    module_name = name_node.text.decode("utf-8")
                    if not module_name.startswith('.'):
                        imports.append(
                            ImportInfo(
                                package_name=module_name.split('.')[0],
                                module_name=module_name,
                                import_type="import",
                                language="python",
                                line_no=name_node.start_point[0] + 1,
                            )
                        )
                else:
                    for sub in child.named_children:
                        if sub.type in ("dotted_name", "aliased_import"):
                            name = sub if sub.type == "dotted_name" else sub.child_by_field_name("name")
                            if name:
                                mod_name = name.text.decode("utf-8")
                                if not mod_name.startswith('.'):
                                    imports.append(
                                        ImportInfo(
                                            package_name=mod_name.split('.')[0],
                                            module_name=mod_name,
                                            import_type="import",
                                            language="python",
                                            line_no=name.start_point[0] + 1,
                                        )
                                    )

            elif child.type == "import_from_statement":
                module_node = child.child_by_field_name("module_name")
                if module_node:
                    mod_name = module_node.text.decode("utf-8")
                    if not mod_name.startswith('.'):
                        imports.append(
                            ImportInfo(
                                package_name=mod_name.split('.')[0],
                                module_name=mod_name,
                                import_type="from_import",
                                language="python",
                                line_no=module_node.start_point[0] + 1,
                            )
                        )

        return imports

    def _extract_javascript_imports(self, code: str) -> list[ImportInfo]:
        """Extract JavaScript imports via tree-sitter tree walking."""
        if not self._ts_available or not self._js_parser:
            logger.warning("tree-sitter JS not available; skipping JS import extraction")
            return []

        tree = self._js_parser.parse(code.encode("utf-8"))
        imports: list[ImportInfo] = []

        def _get_js_package_name(raw_module: str) -> str | None:
            """Parse JS module name to extract package name, handling scopes/deep imports."""
            if raw_module.startswith('.') or raw_module.startswith('/'):
                return None
            
            parts = raw_module.split('/')
            if raw_module.startswith('@'):
                if len(parts) >= 2:
                    return f"{parts[0]}/{parts[1]}"
                return raw_module
            return parts[0]

        def walk_node(node):
            if node.type == "import_statement":
                source = node.child_by_field_name("source")
                if source:
                    module_name = source.text.decode("utf-8").strip("'\"")
                    pkg_name = _get_js_package_name(module_name)
                    if pkg_name:
                        imports.append(
                            ImportInfo(
                                package_name=pkg_name,
                                module_name=module_name,
                                import_type="import",
                                language="javascript",
                                line_no=source.start_point[0] + 1,
                            )
                        )
            elif node.type == "call_expression":
                func = node.child_by_field_name("function")
                if func and func.text.decode("utf-8") == "require":
                    args = node.child_by_field_name("arguments")
                    if args and args.named_child_count > 0:
                        arg = args.named_children[0]
                        if arg.type == "string":
                            module_name = arg.text.decode("utf-8").strip("'\"")
                            pkg_name = _get_js_package_name(module_name)
                            if pkg_name:
                                imports.append(
                                    ImportInfo(
                                        package_name=pkg_name,
                                        module_name=module_name,
                                        import_type="require",
                                        language="javascript",
                                        line_no=arg.start_point[0] + 1,
                                    )
                                )

            for child in node.children:
                walk_node(child)

        walk_node(tree.root_node)
        return imports


def extract_imports(code: str, language: str = "python") -> list[ImportInfo]:
    """Main dispatcher function to extract imports."""
    parser = ASTParser()
    return parser.extract_imports(code, language)
