from __future__ import annotations

"""
Pseudocode Generator Module (Enhanced with AST parsing)
========================================================
Generates human-readable pseudocode from decompiled Java/Smali code.
Uses `javalang` for accurate Java AST parsing when available.

Usage:
    from pseudocode_generator import PseudocodeGenerator
    
    generator = PseudocodeGenerator()
    pseudocode = generator.generate(code, CodeType.JAVA)
    description = generator.generate_description(code, CodeType.JAVA)
"""

import re
import os
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

# Try to import javalang for AST parsing (fallback if not installed/usable)
try:
    import javalang
    _jt = javalang.tree

    def _tree(name: str):
        return getattr(_jt, name, Any)

    CompilationUnit = _tree("CompilationUnit")
    ClassDeclaration = _tree("ClassDeclaration")
    MethodDeclaration = _tree("MethodDeclaration")
    Statement = _tree("Statement")
    IfStatement = _tree("IfStatement")
    WhileStatement = _tree("WhileStatement")
    ForStatement = _tree("ForStatement")
    TryStatement = _tree("TryStatement")
    ReturnStatement = _tree("ReturnStatement")
    ThrowStatement = _tree("ThrowStatement")
    AssertStatement = _tree("AssertStatement")
    SwitchStatement = _tree("SwitchStatement")
    DoWhileStatement = _tree("DoStatement")  # Note: javalang uses DoStatement, not DoWhileStatement
    BlockStatement = _tree("BlockStatement")
    LocalVariableDeclaration = _tree("LocalVariableDeclaration")
    StatementExpression = _tree("StatementExpression")
    Assignment = _tree("Assignment")
    MethodInvocation = _tree("MethodInvocation")
    This = _tree("This")
    SuperMethodInvocation = _tree("SuperMethodInvocation")
    ClassCreator = _tree("ClassCreator")
    ExplicitConstructorInvocation = _tree("ExplicitConstructorInvocation")
    SuperConstructorInvocation = _tree("SuperConstructorInvocation")
    ArrayCreator = _tree("ArrayCreator")
    Cast = _tree("Cast")
    # Note: javalang doesn't have InstanceOf, it uses BinaryOperation with "instanceof" operator
    InstanceOf = _tree("InstanceOf") if hasattr(_jt, "InstanceOf") else None
    BinaryOperation = _tree("BinaryOperation")
    # Note: javalang doesn't have UnaryOperation, prefix/postfix operators are in prefix_operators/postfix_operators attributes
    UnaryOperation = _tree("UnaryOperation") if hasattr(_jt, "UnaryOperation") else None
    TernaryExpression = _tree("TernaryExpression")
    Literal = _tree("Literal")
    MemberReference = _tree("MemberReference")

    JAVALANG_AVAILABLE = True
except Exception as e:
    JAVALANG_AVAILABLE = False
    # Keep names defined for type hints/runtime references when javalang is missing.
    CompilationUnit = ClassDeclaration = MethodDeclaration = Statement = Any
    IfStatement = WhileStatement = ForStatement = TryStatement = ReturnStatement = Any
    ThrowStatement = AssertStatement = SwitchStatement = DoWhileStatement = Any
    BlockStatement = LocalVariableDeclaration = StatementExpression = Any
    Assignment = MethodInvocation = SuperMethodInvocation = ClassCreator = Any
    ExplicitConstructorInvocation = SuperConstructorInvocation = ArrayCreator = Any
    Cast = InstanceOf = BinaryOperation = UnaryOperation = TernaryExpression = Any
    Literal = MemberReference = This = Any
    print(f"Warning: javalang AST unavailable ({e}). Falling back to regex-based pseudocode generator.")


class CodeType(Enum):
    """Types of code that can be analyzed"""
    JAVA = "java"
    KOTLIN = "kotlin"
    SMALI = "smali"
    XML = "xml"
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    C = "c"
    CPP = "cpp"
    JSON = "json"
    TEXT = "text"


@dataclass
class PseudoFunction:
    """Represents a function in pseudocode form"""
    name: str
    parameters: List[str]
    return_type: str
    description: str
    body: List[str]
    complexity: str = "medium"


class PseudocodeGenerator:
    """
    Generates readable pseudocode from decompiled code.
    Uses javalang AST parser for Java/Kotlin (if available).
    Falls back to regex-based parser for Smali and generic code.
    """
    
    # Fallback simplification rules (used when javalang is not available)
    SIMPLIFICATION_RULES = {
        r"Ljava/lang/String;": "String",
        r"Ljava/util/List;": "List",
        r"Ljava/util/Map;": "Map",
        r"Ljava/util/HashMap;": "HashMap",
        r"Ljava/util/ArrayList;": "ArrayList",
        r"Landroid/content/Context;": "Context",
        r"Landroid/app/Activity;": "Activity",
        r"Landroid/content/Intent;": "Intent",
        r"Landroid/database/Cursor;": "Cursor",
        r"Landroid/os/Bundle;": "Bundle",
        r"\(\)V": "() -> void",
        r"\([^)]*\)Ljava/lang/String;": "() -> String",
        r"\([^)]*\)Z": "() -> boolean",
        r"\([^)]*\)I": "() -> int",
    }
    
    # Keywords that indicate important sections (for fallback)
    IMPORTANT_KEYWORDS = {
        "if", "for", "while", "switch", "case", "break",
        "return", "throw", "try", "catch", "finally",
        "synchronized", "volatile", "transient"
    }

    FILE_OPERATION_PATTERNS = [
        (r"\bnew\s+File\s*\(\s*([^)]+)\)", "references a local file path"),
        (r"\bopen\s*\(\s*([^,\n)]+)", "opens a file or resource"),
        (r"\bwith\s+open\s*\(\s*([^,\n)]+)", "opens a file or resource"),
        (r"\bfs\.(?:readFileSync|readFile|createReadStream)\s*\(\s*([^,\n)]+)", "opens a file for reading"),
        (r"\bfs\.(?:writeFileSync|writeFile|appendFile|createWriteStream)\s*\(\s*([^,\n)]+)", "opens a file for writing"),
        (r"\bifstream\s+\w+\s*\(\s*([^,\n)]+)", "opens a file for reading"),
        (r"\bofstream\s+\w+\s*\(\s*([^,\n)]+)", "opens a file for writing"),
        (r"\bFileInputStream\s*\(\s*([^)]+)\)", "opens a file for reading"),
        (r"\bFileOutputStream\s*\(\s*([^)]+)\)", "opens a file for writing"),
        (r"\bFileReader\s*\(\s*([^)]+)\)", "opens a text file for reading"),
        (r"\bFileWriter\s*\(\s*([^)]+)\)", "opens a text file for writing"),
        (r"\bRandomAccessFile\s*\(\s*([^,\n)]+)", "opens a file for random read/write access"),
        (r"\bopenFileInput\s*\(\s*([^)]+)\)", "opens an Android internal file for reading"),
        (r"\bopenFileOutput\s*\(\s*([^)]+)\)", "opens an Android internal file for writing"),
        (r"\bgetSharedPreferences\s*\(\s*([^)]+)\)", "opens an Android SharedPreferences store"),
        (r"\bopenOrCreateDatabase\s*\(\s*([^)]+)\)", "opens or creates a local SQLite database"),
        (r"\bSQLiteDatabase\.openDatabase\s*\(\s*([^)]+)\)", "opens a local SQLite database"),
        (r"\bgetAssets\s*\(\s*\)\.open\s*\(\s*([^)]+)\)", "opens an APK asset for reading"),
        (r"\bgetResources\s*\(\s*\)\.openRawResource\s*\(\s*([^)]+)\)", "opens an Android raw resource"),
        (r"\bfopen\s*\(\s*([^,\n)]+)", "opens a file using native C/C++ file I/O"),
        (r"Landroid/content/res/AssetManager;->open\(.*?\)\s*L", "opens an APK asset for reading"),
        (r"Landroid/content/res/Resources;->openRawResource\(.*?\)\s*L", "opens an Android raw resource"),
        (r"\bdelete\s*\(\s*\)", "deletes a referenced file"),
    ]

    BEHAVIOR_PATTERNS = [
        (r"\bHttpURLConnection\b|\bOkHttpClient\b|\bRetrofit\b|\bURLConnection\b|\bSocket\b|Ljava/net/|Lokhttp3/|Lretrofit2/|\bfetch\s*\(|\baxios\b|\brequests\.|\burllib\.|\bcurl_easy_", "communicate over the network"),
        (r"\bCipher\b|\bMessageDigest\b|\bSecretKeySpec\b|\bMac\b|\bKeyStore\b|Ljavax/crypto/|Ljava/security/|\bcrypto\.|\bhashlib\.|\bopenssl\b", "use cryptography or key material"),
        (r"\bSharedPreferences\b|\bSQLiteDatabase\b|\bCursor\b|\bContentResolver\b|Landroid/content/SharedPreferences;|Landroid/database/sqlite/|Landroid/database/Cursor;|Landroid/content/ContentResolver;", "read or write local app data"),
        (r"\bIntent\b|\bstartActivity\b|\bstartService\b|\bsendBroadcast\b|Landroid/content/Intent;|->startActivity\(|->startService\(|->sendBroadcast\(", "interact with Android components"),
        (r"\bLocationManager\b|\bgetLastKnownLocation\b|\brequestLocationUpdates\b|Landroid/location/LocationManager;", "access device location"),
        (r"\bTelephonyManager\b|\bgetDeviceId\b|\bgetImei\b|\bgetSubscriberId\b|Landroid/telephony/TelephonyManager;", "access phone or subscriber identifiers"),
        (r"\bRuntime\.getRuntime\(\)\.exec\b|\bProcessBuilder\b|Ljava/lang/Runtime;->exec\(|Ljava/lang/ProcessBuilder;|\bsubprocess\.|\bos\.system\b|\bchild_process\b|\bsystem\s*\(", "execute system commands"),
        (r"\bClass\.forName\b|\bgetMethod\b|\binvoke\s*\(|Ljava/lang/Class;->forName\(|Ljava/lang/reflect/", "use reflection or dynamic invocation"),
        (r"\bBase64\b|\bencodeToString\b|\bdecode\b|Landroid/util/Base64;|Ljava/util/Base64;", "encode or decode data"),
        (r"\bLog\.[diewv]\b|\bSystem\.out\.print|Landroid/util/Log;->|Ljava/io/PrintStream;->print", "write diagnostic log output"),
    ]
    
    def __init__(self):
        # For fallback parsing
        self.function_pattern = re.compile(
            r"(?:public|private|protected|static)?\s*(?:void|int|String|boolean|float|double|\w+)\s+(\w+)\s*\(([^)]*)\)\s*\{"
        )
    
    # ========== PUBLIC API (unchanged signatures) ==========
    
    def generate(self, code: str, code_type: CodeType = CodeType.JAVA) -> str:
        """
        Generate pseudocode from decompiled code.
        
        Args:
            code: The decompiled source code
            code_type: Type of code (JAVA, KOTLIN, SMALI, XML)
            
        Returns:
            Pseudocode representation as string
        """
        if not code or not code.strip():
            return "// No code to analyze\n"
        
        if code_type == CodeType.JAVA:
            if JAVALANG_AVAILABLE:
                return self._generate_from_java_ast(code)
            else:
                return self._generate_from_java_fallback(code)
        elif code_type == CodeType.KOTLIN:
            # Kotlin can also be parsed by javalang (limited support)
            if JAVALANG_AVAILABLE:
                return self._generate_from_java_ast(code)
            else:
                return self._generate_from_kotlin_fallback(code)
        elif code_type == CodeType.SMALI:
            return self._generate_from_smali(code)
        else:
            return self._generate_generic(code)
    
    def extract_functions(self, code: str) -> List[PseudoFunction]:
        """
        Extract and analyze all functions in the code.
        
        Returns:
            List of PseudoFunction objects
        """
        if JAVALANG_AVAILABLE:
            return self._extract_functions_ast(code)
        else:
            return self._extract_functions_fallback(code)
    
    def generate_summary(self, code: str) -> str:
        """Generate a brief summary of the code"""
        if JAVALANG_AVAILABLE:
            return self._generate_summary_ast(code)
        else:
            return self._generate_summary_fallback(code)

    def generate_description(
        self,
        code: str,
        code_type: CodeType = CodeType.JAVA,
        file_name: Optional[str] = None,
    ) -> str:
        """
        Generate an English-language behavioral description of decompiled code.

        The description focuses on how opened files/resources are used and what
        the discovered functions appear to do.
        """
        if not code or not code.strip():
            return "English Description\n===================\nNo code was provided for analysis.\n"

        functions = self._extract_functions_for_description(code, code_type)
        file_usages = self._extract_file_usages(code)
        behaviors = self._extract_behavior_indicators(code)

        title = f"English Description for {file_name}" if file_name else "English Description"
        lines = [title, "=" * len(title), ""]
        lines.extend(self._describe_overall_behavior(code, code_type, functions, file_usages, behaviors))
        lines.append("")
        lines.extend(self._format_file_usage_description(file_usages))
        lines.append("")
        if code_type in {CodeType.XML, CodeType.JSON, CodeType.TEXT}:
            lines.extend(self._format_structured_file_description(code, code_type))
        else:
            lines.extend(self._format_function_descriptions(functions))
        return "\n".join(lines).rstrip() + "\n"

    def _extract_functions_for_description(self, code: str, code_type: CodeType) -> List[PseudoFunction]:
        if code_type == CodeType.SMALI:
            return self._extract_functions_smali(code)
        if code_type == CodeType.PYTHON:
            return self._extract_functions_python(code)
        if code_type == CodeType.JAVASCRIPT:
            return self._extract_functions_javascript(code)
        if code_type in {CodeType.C, CodeType.CPP}:
            return self._extract_functions_c_like(code)
        if code_type in {CodeType.XML, CodeType.JSON, CodeType.TEXT}:
            return []

        functions = self.extract_functions(code)
        if functions:
            return functions
        return self._extract_functions_fallback(code)

    def _extract_file_usages(self, code: str) -> List[Dict[str, str]]:
        usages = []
        seen = set()
        for pattern, action in self.FILE_OPERATION_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                target = self._clean_reference(match.group(1) if match.groups() else "current file object")
                context = self._line_context(code, match.start())
                key = (action, target, context)
                if key in seen:
                    continue
                seen.add(key)
                usages.append({
                    "target": target,
                    "action": action,
                    "purpose": self._infer_file_purpose(target, context),
                    "context": context,
                })
        return usages[:20]

    def _extract_behavior_indicators(self, code: str) -> List[str]:
        indicators = []
        for pattern, description in self.BEHAVIOR_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                indicators.append(description)
        return indicators

    def _describe_overall_behavior(
        self,
        code: str,
        code_type: CodeType,
        functions: List[PseudoFunction],
        file_usages: List[Dict[str, str]],
        behaviors: List[str],
    ) -> List[str]:
        lines = ["Behavior Summary:"]
        if functions:
            lines.append(f"- Defines {len(functions)} function(s)/method(s) that organize the file's behavior.")
        elif code_type in {CodeType.XML, CodeType.JSON, CodeType.TEXT}:
            lines.append("- This file does not define executable functions; it is handled as structured data/configuration.")
        else:
            lines.append("- No clear function declarations were found; behavior may be inline, obfuscated, or partial.")

        if file_usages:
            lines.append(f"- Uses {len(file_usages)} file/resource operation(s), mainly to {self._join_phrases(sorted({u['purpose'] for u in file_usages}))}.")
        else:
            lines.append("- No obvious file open/read/write operation was detected.")

        if behaviors:
            lines.append(f"- Also appears to {self._join_phrases(behaviors)}.")
        elif code_type == CodeType.XML:
            lines.append("- This appears to be structured XML data or configuration rather than executable code.")
        elif code_type == CodeType.JSON:
            lines.append("- This appears to be structured JSON data or configuration rather than executable code.")
        elif code_type == CodeType.TEXT:
            lines.append("- This appears to be text/configuration data rather than executable code.")
        else:
            lines.append("- No high-risk Android, network, crypto, or command-execution behavior was obvious from simple pattern analysis.")
        return lines

    def _format_file_usage_description(self, file_usages: List[Dict[str, str]]) -> List[str]:
        lines = ["File / Resource Usage:"]
        if not file_usages:
            lines.append("- No explicit file or resource opening was detected.")
            return lines

        for usage in file_usages:
            lines.append(
                f"- `{usage['target']}`: {usage['action']}. It is likely used to {usage['purpose']}."
            )
        return lines

    def _format_function_descriptions(self, functions: List[PseudoFunction]) -> List[str]:
        lines = ["Function Descriptions:"]
        if not functions:
            lines.append("- No functions could be extracted from this file.")
            return lines

        for func in functions[:15]:
            lines.append(
                f"- `{func.name}`: {self._describe_function(func)} "
                f"Returns `{func.return_type}` and has {func.complexity} apparent complexity."
            )
        if len(functions) > 15:
            lines.append(f"- ... and {len(functions) - 15} more function(s) not shown.")
        return lines

    def _format_structured_file_description(self, code: str, code_type: CodeType) -> List[str]:
        if code_type == CodeType.XML:
            return self._format_xml_description(code)
        if code_type == CodeType.JSON:
            return self._format_json_description(code)
        return self._format_text_description(code)

    def _format_xml_description(self, code: str) -> List[str]:
        tags = re.findall(r"<\s*([A-Za-z_][\w:.-]*)\b", code)
        unique_tags = []
        for tag in tags:
            if tag not in unique_tags and not tag.startswith("?"):
                unique_tags.append(tag)

        lines = ["Structured File Description:"]
        if "manifest" in unique_tags:
            lines.append("- This appears to be an Android manifest or manifest-like XML file.")
        elif "resources" in unique_tags:
            lines.append("- This appears to define Android resources such as strings, styles, colors, arrays, or IDs.")
        elif any(tag in unique_tags for tag in ["LinearLayout", "ConstraintLayout", "RelativeLayout", "TextView", "Button"]):
            lines.append("- This appears to define an Android UI layout.")
        else:
            lines.append("- This XML file defines structured configuration or resource data.")

        permissions = re.findall(r"uses-permission[^>]+android:name=[\"']([^\"']+)[\"']", code)
        components = [tag for tag in unique_tags if tag in {"activity", "service", "receiver", "provider"}]
        if permissions:
            lines.append(f"- Declares permissions: {', '.join(permissions[:8])}.")
        if components:
            lines.append(f"- Declares Android component types: {', '.join(sorted(set(components)))}.")
        if unique_tags:
            lines.append(f"- Main tags found: {', '.join(unique_tags[:12])}.")
        return lines

    def _format_json_description(self, code: str) -> List[str]:
        keys = re.findall(r'"([^"]+)"\s*:', code)
        unique_keys = []
        for key in keys:
            if key not in unique_keys:
                unique_keys.append(key)

        sensitive = [
            key for key in unique_keys
            if re.search(r"api[_-]?key|secret|token|password|credential|client[_-]?id|private", key, re.IGNORECASE)
        ]
        lines = ["Structured File Description:"]
        lines.append("- This JSON file appears to contain structured data or configuration values.")
        if unique_keys:
            lines.append(f"- Main keys found: {', '.join(unique_keys[:15])}.")
        if sensitive:
            lines.append(f"- Potentially sensitive keys found: {', '.join(sensitive[:8])}.")
        return lines

    def _format_text_description(self, code: str) -> List[str]:
        non_empty_lines = [line.strip() for line in code.splitlines() if line.strip()]
        lines = ["Structured File Description:"]
        lines.append(f"- This text-like file contains {len(non_empty_lines)} non-empty line(s).")
        if any("=" in line for line in non_empty_lines[:50]):
            lines.append("- It appears to contain key/value configuration entries.")
        if any(re.search(r"https?://", line) for line in non_empty_lines):
            lines.append("- It contains URL-like values that may reference remote services or resources.")
        return lines

    def _extract_functions_smali(self, code: str) -> List[PseudoFunction]:
        functions = []
        current_name = None
        current_body = []

        for raw_line in code.splitlines():
            line = raw_line.strip()
            if line.startswith(".method"):
                current_name = self._extract_smali_method(line)
                current_body = []
                continue
            if line.startswith(".end method") and current_name:
                functions.append(PseudoFunction(
                    name=current_name,
                    parameters=[],
                    return_type="unknown",
                    description=f"Smali method: {current_name}",
                    body=current_body,
                    complexity=self._estimate_complexity(current_body),
                ))
                current_name = None
                current_body = []
                continue
            if current_name and line:
                current_body.append(line)

        return functions

    def _extract_functions_python(self, code: str) -> List[PseudoFunction]:
        functions = []
        lines = code.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^(\s*)def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:", line)
            if not match:
                continue
            indent, name, params, return_type = match.groups()
            body = self._collect_indented_body(lines, index + 1, len(indent))
            functions.append(PseudoFunction(
                name=name,
                parameters=[p.strip() for p in params.split(",") if p.strip()],
                return_type=(return_type or "unknown").strip(),
                description=f"Python function: {name}",
                body=body,
                complexity=self._estimate_complexity(body),
            ))
        return functions

    def _extract_functions_javascript(self, code: str) -> List[PseudoFunction]:
        patterns = [
            r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{",
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{",
            r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function\s*\(([^)]*)\)\s*\{",
            r"\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{",
        ]
        return self._extract_brace_functions(code, patterns, "JavaScript function")

    def _extract_functions_c_like(self, code: str) -> List[PseudoFunction]:
        patterns = [
            r"\b([A-Za-z_][\w:<>\*&\s]+?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{",
        ]
        functions = []
        for match in re.finditer(patterns[0], code, re.MULTILINE):
            return_type = re.sub(r"\s+", " ", match.group(1)).strip()
            name = match.group(2)
            if name in {"if", "for", "while", "switch", "catch"}:
                continue
            body = self._collect_brace_body(code, match.end() - 1)
            functions.append(PseudoFunction(
                name=name,
                parameters=[p.strip() for p in match.group(3).split(",") if p.strip()],
                return_type=return_type or "unknown",
                description=f"C/C++ function: {name}",
                body=body,
                complexity=self._estimate_complexity(body),
            ))
        return functions

    def _extract_brace_functions(self, code: str, patterns: List[str], description_prefix: str) -> List[PseudoFunction]:
        functions = []
        seen = set()
        for pattern in patterns:
            for match in re.finditer(pattern, code, re.MULTILINE):
                name = match.group(1)
                if name in seen or name in {"if", "for", "while", "switch", "catch"}:
                    continue
                seen.add(name)
                body = self._collect_brace_body(code, match.end() - 1)
                functions.append(PseudoFunction(
                    name=name,
                    parameters=[p.strip() for p in match.group(2).split(",") if p.strip()],
                    return_type="unknown",
                    description=f"{description_prefix}: {name}",
                    body=body,
                    complexity=self._estimate_complexity(body),
                ))
        return functions

    def _collect_brace_body(self, code: str, opening_brace_index: int) -> List[str]:
        depth = 0
        body_chars = []
        for char in code[opening_brace_index:]:
            if char == "{":
                depth += 1
                if depth == 1:
                    continue
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            if depth >= 1:
                body_chars.append(char)
        return [line.strip() for line in "".join(body_chars).splitlines() if line.strip()]

    def _collect_indented_body(self, lines: List[str], start_index: int, parent_indent: int) -> List[str]:
        body = []
        for line in lines[start_index:]:
            stripped = line.strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= parent_indent and not stripped.startswith(("#", "@")):
                break
            body.append(stripped)
        return body

    def _describe_function(self, func: PseudoFunction) -> str:
        name_words = self._split_identifier(func.name)
        body = "\n".join(func.body).lower()
        hints = []

        if self._looks_like_smali_body(func.body):
            return self._describe_smali_function(func)

        if any(word in name_words for word in ["load", "read", "parse", "decode"]):
            hints.append("load or parse data")
        if any(word in name_words for word in ["save", "write", "store", "persist"]):
            hints.append("store data")
        if any(word in name_words for word in ["delete", "remove", "clear"]):
            hints.append("remove data")
        if any(word in name_words for word in ["init", "create", "setup", "start"]):
            hints.append("initialize application state")
        if any(word in name_words for word in ["check", "verify", "validate", "is", "has"]):
            hints.append("validate a condition")
        if any(word in name_words for word in ["send", "post", "request", "download", "upload", "connect"]):
            hints.append("handle communication or data transfer")

        for pattern, description in self.BEHAVIOR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE) and description not in hints:
                hints.append(description)

        file_usages = self._extract_file_usages(body)
        if file_usages:
            hints.append(f"use file/resource access to {self._join_phrases(sorted({u['purpose'] for u in file_usages}))}")

        if "return" in body:
            hints.append("produce a result for callers")
        if any(keyword in body for keyword in [" if ", "for ", "while ", "switch "]):
            hints.append("branch or loop based on runtime conditions")

        if not hints:
            readable_name = " ".join(name_words) if name_words else func.name
            return f"appears to implement `{readable_name}` logic."
        return f"appears to {self._join_phrases(hints)}."

    def _looks_like_smali_body(self, body_lines: List[str]) -> bool:
        smali_opcode = re.compile(
            r"^\s*(\.locals|\.param|invoke-|[is]get|[is]put|const(?:/|-)|move-|return-|new-instance|new-array|check-cast|if-|goto|throw)",
            re.IGNORECASE,
        )
        return any(smali_opcode.search(line) for line in body_lines)

    def _describe_smali_function(self, func: PseudoFunction) -> str:
        body = "\n".join(func.body).lower()
        hints = []

        if func.name in {"<init>", "constructor"}:
            hints.append("initialize an object instance")
        elif func.name == "<clinit>":
            hints.append("initialize static class data")

        if "invoke-" in body:
            hints.append("call other methods")
        if "invoke-static" in body:
            hints.append("call static helper functions")
        if "invoke-virtual" in body or "invoke-interface" in body:
            hints.append("call object or interface methods")
        if "iget" in body or "sget" in body:
            hints.append("read object or static fields")
        if "iput" in body or "sput" in body:
            hints.append("write object or static fields")
        if "new-instance" in body or "new-array" in body:
            hints.append("create objects or arrays")
        if "if-" in body or "packed-switch" in body or "sparse-switch" in body:
            hints.append("branch based on runtime conditions")
        if "goto" in body:
            hints.append("jump between bytecode blocks")
        if "return" in body:
            hints.append("return control or data to the caller")
        if "throw" in body or ".catch" in body:
            hints.append("handle or raise exceptions")

        for pattern, description in self.BEHAVIOR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                hints.append(description)

        if not hints:
            return "appears to contain low-level Smali instructions, but no specific behavior pattern was identified."
        return f"appears to {self._join_phrases(hints)}."

    def _infer_file_purpose(self, target: str, context: str) -> str:
        text = f"{target} {context}".lower()
        if any(token in text for token in ["pref", "setting", "config", ".xml", ".json", ".properties"]):
            return "load or store configuration/settings"
        if any(token in text for token in ["db", "sqlite", ".sqlite", ".db"]):
            return "read or update a local database"
        if any(token in text for token in ["cache", "tmp", "temp"]):
            return "cache temporary data"
        if any(token in text for token in ["log", "trace"]):
            return "write or inspect diagnostic logs"
        if any(token in text for token in ["key", "cert", "pem", "keystore", "token", "secret"]):
            return "read or store security-sensitive material"
        if any(token in text for token in ["image", "png", "jpg", "jpeg", "webp", "bitmap"]):
            return "read or write image/media data"
        if any(token in text for token in ["read", "input", "reader"]):
            return "read data into the program"
        if any(token in text for token in ["write", "output", "writer", "append"]):
            return "write data produced by the program"
        if "delete" in text:
            return "remove stored data"
        return "access application data or resources"

    def _clean_reference(self, value: str) -> str:
        value = re.sub(r"\s+", " ", value).strip()
        value = value.strip(";")
        if len(value) > 80:
            value = value[:77] + "..."
        return value or "unknown target"

    def _line_context(self, code: str, offset: int) -> str:
        start = code.rfind("\n", 0, offset) + 1
        end = code.find("\n", offset)
        if end == -1:
            end = len(code)
        return code[start:end].strip()

    def _split_identifier(self, name: str) -> List[str]:
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
        return [part.lower() for part in re.split(r"[^A-Za-z0-9]+|\s+", spaced) if part]

    def _join_phrases(self, phrases: List[str]) -> str:
        unique = []
        for phrase in phrases:
            if phrase and phrase not in unique:
                unique.append(phrase)
        if not unique:
            return "perform general processing"
        if len(unique) == 1:
            return unique[0]
        if len(unique) == 2:
            return f"{unique[0]} and {unique[1]}"
        return ", ".join(unique[:-1]) + f", and {unique[-1]}"
    
    # ========== AST-BASED PARSING (Primary, high-quality) ==========
    
    def _generate_from_java_ast(self, code: str) -> str:
        """Generate pseudocode using javalang AST (Java/Kotlin)."""
        try:
            tree = javalang.parse.parse(code)
        except Exception:
            # Fallback silently if parsing fails on decompiled/partial sources.
            return self._generate_from_java_fallback(code)
        
        pseudocode_lines = []
        
        # Find the main class(es)
        for path, node in tree:
            if isinstance(node, ClassDeclaration):
                pseudocode_lines.append(f"class {node.name}:")
                if node.extends:
                    pseudocode_lines.append(f"    extends {node.extends.name}")
                if node.implements:
                    impls = ", ".join(i.name for i in node.implements)
                    pseudocode_lines.append(f"    implements {impls}")
                pseudocode_lines.append("")
                
                # Process fields
                for field in node.fields:
                    for declarator in field.declarators:
                        pseudocode_lines.append(f"    attribute {declarator.name}: {field.type.name}")
                if node.fields:
                    pseudocode_lines.append("")
                
                # Process methods
                for method in node.methods:
                    pseudocode_lines.extend(self._method_to_pseudocode_enhanced(method, indent=1))
        
        if not pseudocode_lines:
            # No class found? Try to just output methods as top-level functions
            for path, node in tree:
                if isinstance(node, MethodDeclaration):
                    pseudocode_lines.extend(self._method_to_pseudocode_enhanced(node, indent=0))
        
        return "\n".join(pseudocode_lines)
    
    def _method_to_pseudocode_enhanced(self, method: MethodDeclaration, indent: int = 1) -> List[str]:
        """Convert a Java method declaration into simplified pseudocode lines with better abstraction."""
        lines = []
        indent_str = "    " * indent
        
        # Determine method purpose from name
        method_purpose = self._infer_method_purpose(method.name)
        
        # Method signature
        params = []
        for param in method.parameters:
            param_type = param.type.name if hasattr(param.type, 'name') else str(param.type)
            params.append(f"{param.name}: {param_type}")
        param_str = ", ".join(params) if params else ""
        
        return_type = method.return_type.name if method.return_type and hasattr(method.return_type, 'name') else (str(method.return_type) if method.return_type else "void")
        
        # Create simplified method signature
        lines.append(f"{indent_str}function {method.name}({param_str}):")
        lines.append(f"{indent_str}    // Purpose: {method_purpose}")
        lines.append(f"{indent_str}    // Returns: {return_type}")
        
        # Method body (simplified)
        body_processed = False
        if method.body:
            try:
                # javalang returns method.body as a list of statements
                body_statements = None
                
                if isinstance(method.body, list):
                    body_statements = method.body
                elif hasattr(method.body, 'statements'):
                    body_statements = method.body.statements
                
                if body_statements and len(body_statements) > 0:
                    # Count control flow and method calls for complexity estimation
                    complexity_info = self._analyze_complexity(body_statements)
                    if complexity_info['high_complexity']:
                        lines.append(f"{indent_str}    // Complexity: High")
                    
                    body_lines = self._statements_to_pseudocode_enhanced(body_statements, indent + 1, complexity_info)
                    if body_lines:
                        lines.extend(body_lines)
                        body_processed = True
            except Exception as e:
                pass
        
        if not body_processed:
            lines.append(f"{indent_str}    // (empty or native method)")
        
        lines.append("")  # blank line after method
        return lines
    
    def _statements_to_pseudocode_enhanced(self, statements: List[Statement], indent: int, complexity_info: Dict = None) -> List[str]:
        """Recursively convert AST statements to simplified, abstracted pseudocode."""
        if complexity_info is None:
            complexity_info = {'high_complexity': False, 'statement_count': len(statements)}
        
        lines = []
        indent_str = "    " * indent
        
        # If too many statements, provide summary instead
        if len(statements) > 15 and complexity_info['high_complexity']:
            lines.append(f"{indent_str}// Complex logic with multiple control flows")
            control_flow_count = 0
            for s in statements:
                try:
                    if isinstance(s, (IfStatement, WhileStatement, ForStatement, SwitchStatement, TryStatement)):
                        control_flow_count += 1
                except TypeError:
                    pass
            if control_flow_count > 0:
                lines.append(f"{indent_str}// Contains {control_flow_count} control flow blocks")
            method_calls = sum(1 for s in statements if self._contains_method_call(s))
            if method_calls > 0:
                lines.append(f"{indent_str}// Makes {method_calls} method call(s)")
            return lines
        
        for i, stmt in enumerate(statements):
            # Skip empty statements
            if not stmt:
                continue
            
            stmt_handled = False
            
            try:
                # If statement
                if isinstance(stmt, IfStatement):
                    condition = self._expr_to_pseudocode_simplified(stmt.condition)
                    lines.append(f"{indent_str}if {condition}:")
                    
                    # Process then statement
                    if stmt.then_statement:
                        then_stmts = []
                        if isinstance(stmt.then_statement, BlockStatement) and hasattr(stmt.then_statement, 'statements'):
                            then_stmts = stmt.then_statement.statements
                        else:
                            then_stmts = [stmt.then_statement]
                        then_lines = self._statements_to_pseudocode_enhanced(then_stmts, indent + 1)
                        lines.extend(then_lines or [f"{indent_str}    // (empty)"])
                    else:
                        lines.append(f"{indent_str}    // (empty)")
                    
                    # Process else statement
                    if stmt.else_statement:
                        lines.append(f"{indent_str}else:")
                        else_stmts = []
                        if isinstance(stmt.else_statement, BlockStatement) and hasattr(stmt.else_statement, 'statements'):
                            else_stmts = stmt.else_statement.statements
                        else:
                            else_stmts = [stmt.else_statement]
                        else_lines = self._statements_to_pseudocode_enhanced(else_stmts, indent + 1)
                        lines.extend(else_lines or [f"{indent_str}    // (empty)"])
                    stmt_handled = True
                
                # While loop
                elif isinstance(stmt, WhileStatement):
                    condition = self._expr_to_pseudocode_simplified(stmt.condition)
                    lines.append(f"{indent_str}while {condition}:")
                    body_stmts = []
                    if stmt.body:
                        if isinstance(stmt.body, BlockStatement) and hasattr(stmt.body, 'statements'):
                            body_stmts = stmt.body.statements
                        else:
                            body_stmts = [stmt.body]
                    body_lines = self._statements_to_pseudocode_enhanced(body_stmts, indent + 1)
                    lines.extend(body_lines or [f"{indent_str}    // (empty)"])
                    stmt_handled = True
                
                # For loop
                elif isinstance(stmt, ForStatement):
                    # Simplify for loop - extract init and condition properly
                    init_str = ""
                    condition_str = ""
                    
                    if hasattr(stmt.control, 'init') and stmt.control.init:
                        try:
                            init_str = self._expr_to_pseudocode_simplified(stmt.control.init)
                        except:
                            init_str = str(stmt.control.init)
                    
                    if hasattr(stmt.control, 'condition') and stmt.control.condition:
                        try:
                            condition_str = self._expr_to_pseudocode_simplified(stmt.control.condition)
                        except:
                            condition_str = str(stmt.control.condition)
                    
                    if init_str and condition_str:
                        lines.append(f"{indent_str}for {init_str}; {condition_str}:")
                    elif init_str:
                        lines.append(f"{indent_str}for {init_str}:")
                    else:
                        lines.append(f"{indent_str}for [iteration]:")
                    
                    body_stmts = []
                    if stmt.body:
                        if isinstance(stmt.body, BlockStatement) and hasattr(stmt.body, 'statements'):
                            body_stmts = stmt.body.statements
                        else:
                            body_stmts = [stmt.body]
                    body_lines = self._statements_to_pseudocode_enhanced(body_stmts, indent + 1)
                    lines.extend(body_lines or [f"{indent_str}    // (empty)"])
                    stmt_handled = True
                
                # Do-while loop
                elif isinstance(stmt, DoWhileStatement):
                    condition = self._expr_to_pseudocode_simplified(stmt.condition)
                    lines.append(f"{indent_str}repeat:")
                    body_stmts = []
                    if stmt.body:
                        if isinstance(stmt.body, BlockStatement) and hasattr(stmt.body, 'statements'):
                            body_stmts = stmt.body.statements
                        else:
                            body_stmts = [stmt.body]
                    body_lines = self._statements_to_pseudocode_enhanced(body_stmts, indent + 1)
                    lines.extend(body_lines or [f"{indent_str}    // (empty)"])
                    lines.append(f"{indent_str}until {condition}")
                    stmt_handled = True
                
                # Try-Catch
                elif isinstance(stmt, TryStatement):
                    lines.append(f"{indent_str}try:")
                    try_stmts = []
                    if stmt.block:
                        if isinstance(stmt.block, BlockStatement) and hasattr(stmt.block, 'statements'):
                            try_stmts = stmt.block.statements
                        else:
                            try_stmts = [stmt.block]
                    try_lines = self._statements_to_pseudocode_enhanced(try_stmts, indent + 1)
                    lines.extend(try_lines or [f"{indent_str}    // (empty)"])
                    
                    for catch in stmt.catches:
                        catch_type = catch.parameter.type.name if hasattr(catch.parameter.type, 'name') else str(catch.parameter.type)
                        lines.append(f"{indent_str}catch ({catch_type}):")
                        catch_stmts = []
                        if catch.block:
                            if isinstance(catch.block, BlockStatement) and hasattr(catch.block, 'statements'):
                                catch_stmts = catch.block.statements
                            else:
                                catch_stmts = [catch.block]
                        catch_lines = self._statements_to_pseudocode_enhanced(catch_stmts, indent + 1)
                        lines.extend(catch_lines or [f"{indent_str}    // (empty)"])
                    
                    if stmt.finally_block:
                        lines.append(f"{indent_str}finally:")
                        finally_stmts = []
                        if isinstance(stmt.finally_block, BlockStatement) and hasattr(stmt.finally_block, 'statements'):
                            finally_stmts = stmt.finally_block.statements
                        else:
                            finally_stmts = [stmt.finally_block]
                        finally_lines = self._statements_to_pseudocode_enhanced(finally_stmts, indent + 1)
                        lines.extend(finally_lines or [f"{indent_str}    // (empty)"])
                    stmt_handled = True
                
                # Return statement
                elif isinstance(stmt, ReturnStatement):
                    if stmt.expression:
                        try:
                            expr = self._expr_to_pseudocode_simplified(stmt.expression)
                            if expr:
                                lines.append(f"{indent_str}return {expr}")
                            else:
                                lines.append(f"{indent_str}return")
                        except:
                            # Fallback if expression parsing fails
                            lines.append(f"{indent_str}return")
                    else:
                        lines.append(f"{indent_str}return")
                    stmt_handled = True
                
                # Throw statement
                elif isinstance(stmt, ThrowStatement):
                    try:
                        expr = self._expr_to_pseudocode_simplified(stmt.expression)
                        if expr:
                            lines.append(f"{indent_str}throw {expr}")
                        else:
                            lines.append(f"{indent_str}throw")
                    except:
                        lines.append(f"{indent_str}throw")
                    stmt_handled = True
                
                # Switch statement
                elif isinstance(stmt, SwitchStatement):
                    selector = self._expr_to_pseudocode_simplified(stmt.selector)
                    lines.append(f"{indent_str}switch {selector}:")
                    for case in stmt.cases:
                        if case.case:
                            case_expr = self._expr_to_pseudocode_simplified(case.case[0])
                            lines.append(f"{indent_str}    case {case_expr}:")
                        else:
                            lines.append(f"{indent_str}    default:")
                        case_lines = self._statements_to_pseudocode_enhanced(case.statements, indent + 2) if case.statements else []
                        lines.extend(case_lines or [f"{indent_str}        // (empty)"])
                    stmt_handled = True
                
                # Local variable declaration
                elif isinstance(stmt, LocalVariableDeclaration):
                    for declarator in stmt.declarators:
                        var_type = stmt.type.name if hasattr(stmt.type, 'name') else str(stmt.type)
                        if declarator.initializer:
                            try:
                                init_expr = self._expr_to_pseudocode_simplified(declarator.initializer)
                                lines.append(f"{indent_str}let {declarator.name}: {var_type} = {init_expr}")
                            except:
                                lines.append(f"{indent_str}let {declarator.name}: {var_type}")
                        else:
                            lines.append(f"{indent_str}let {declarator.name}: {var_type}")
                    stmt_handled = True
                
                # Expression statement
                elif isinstance(stmt, StatementExpression):
                    try:
                        expr_str = self._expr_to_pseudocode_simplified(stmt.expression)
                        if expr_str and expr_str.strip():
                            lines.append(f"{indent_str}{expr_str}")
                    except:
                        # If expression parsing fails, show generic comment
                        pass
                    stmt_handled = True
                
                # Block statement
                elif isinstance(stmt, BlockStatement):
                    block_lines = self._statements_to_pseudocode_enhanced(stmt.statements, indent) if hasattr(stmt, 'statements') and stmt.statements else []
                    lines.extend(block_lines if block_lines else [f"{indent_str}// (empty block)"])
                    stmt_handled = True
            
            except TypeError as te:
                # isinstance check failed due to Any type
                pass
            except Exception as e:
                # Other exceptions - log but continue
                pass
            
            # If not handled, try to get generic info from statement
            if not stmt_handled:
                try:
                    stmt_str = str(stmt)
                    if stmt_str and len(stmt_str) < 100:
                        lines.append(f"{indent_str}// {stmt_str}")
                except:
                    pass
        
        return lines
    
    def _expr_to_pseudocode_simplified(self, expr) -> str:
        """Convert expressions to simplified, abstracted pseudocode."""
        if expr is None:
            return ""
        
        DEBUG = os.environ.get('DEBUG_PSEUDOCODE') == '1'
        
        try:
            # Literals
            if isinstance(expr, Literal):
                return str(expr.value)
            
            # Variable Declaration (for use in for loops)
            if hasattr(expr, '__class__') and expr.__class__.__name__ == 'VariableDeclaration':
                # Handle VariableDeclaration from javalang
                if hasattr(expr, 'declarators') and expr.declarators:
                    decl = expr.declarators[0]  # Get first declarator
                    var_type = expr.type.name if hasattr(expr.type, 'name') else str(expr.type)
                    if hasattr(decl, 'initializer') and decl.initializer:
                        init_val = self._expr_to_pseudocode_simplified(decl.initializer)
                        return f"{decl.name} = {init_val}"
                    else:
                        return f"{decl.name}"
            
            # Binary operations
            if isinstance(expr, BinaryOperation):
                left = self._expr_to_pseudocode_simplified(expr.operandl)
                right = self._expr_to_pseudocode_simplified(expr.operandr)
                op = expr.operator
                
                # Simplify operators to human-readable form
                op_map = {
                    "==": "==",
                    "!=": "!=",
                    "&&": "and",
                    "||": "or",
                    "+": "+",
                    "-": "-",
                    "*": "*",
                    "/": "/",
                    "%": "mod",
                    "<": "<",
                    "<=": "<=",
                    ">": ">",
                    ">=": ">=",
                }
                pseud_op = op_map.get(op, op)
                return f"({left} {pseud_op} {right})"
            
            # Unary operations (only if available in javalang)
            if UnaryOperation is not None and isinstance(expr, UnaryOperation):
                operand = self._expr_to_pseudocode_simplified(expr.operand)
                op = expr.operator
                if op == "!":
                    return f"not {operand}"
                elif op == "-":
                    return f"-{operand}"
                else:
                    return f"{op}{operand}"
            
            # Ternary expression
            if isinstance(expr, TernaryExpression):
                cond = self._expr_to_pseudocode_simplified(expr.condition)
                true_val = self._expr_to_pseudocode_simplified(expr.true)
                false_val = self._expr_to_pseudocode_simplified(expr.false)
                return f"({true_val} if {cond} else {false_val})"
            
            # Assignment
            if isinstance(expr, Assignment):
                left = self._expr_to_pseudocode_simplified(expr.expressionl)
                right = self._expr_to_pseudocode_simplified(expr.value)
                return f"{left} = {right}"
            
            # Method invocation
            if isinstance(expr, MethodInvocation):
                if DEBUG:
                    print(f"[DEBUG] Handling MethodInvocation: {expr.member}")
                method_name = expr.member
                args = []
                try:
                    if expr.arguments:
                        for arg in expr.arguments:
                            arg_str = self._expr_to_pseudocode_simplified(arg)
                            if arg_str:
                                args.append(arg_str)
                except Exception as e:
                    if DEBUG:
                        print(f"[DEBUG] Error processing arguments: {e}")
                
                args_str = ", ".join(args) if args else ""
                
                # Extract qualifier/object - it may be a string or an AST node
                qualifier_str = ""
                if expr.qualifier:
                    # In javalang, qualifier is often already a string
                    if isinstance(expr.qualifier, str):
                        qualifier_str = expr.qualifier.strip() if expr.qualifier.strip() else ""
                        if DEBUG:
                            print(f"[DEBUG] String qualifier extracted: '{qualifier_str}'")
                    else:
                        try:
                            qual = self._expr_to_pseudocode_simplified(expr.qualifier)
                            if qual and qual not in ("<>", ""):
                                qualifier_str = qual
                            if DEBUG:
                                print(f"[DEBUG] AST qualifier extracted: '{qualifier_str}'")
                        except Exception as e:
                            if DEBUG:
                                print(f"[DEBUG] Error processing qualifier: {e}")
                
                # Handle prefix operators (like ! in !obj.method())
                prefix = ""
                if hasattr(expr, 'prefix_operators') and expr.prefix_operators:
                    for op in expr.prefix_operators:
                        if op == "!":
                            prefix = "not "
                        else:
                            prefix = f"{op}"
                
                # Format method call
                if qualifier_str:
                    result = f"{qualifier_str}.{method_name}({args_str})"
                else:
                    result = f"{method_name}({args_str})"
                
                if DEBUG:
                    print(f"[DEBUG] Final MethodInvocation result: '{result}'")
                
                if prefix:
                    return f"{prefix}({result})"
                return result
            
            # Member reference
            if isinstance(expr, MemberReference):
                member_name = expr.member
                
                # Handle postfix operators (like ++ or --)
                postfix = ""
                if hasattr(expr, 'postfix_operators') and expr.postfix_operators:
                    postfix = "".join(expr.postfix_operators)
                
                try:
                    if expr.qualifier:
                        # Qualifier may be a string or AST node
                        if isinstance(expr.qualifier, str):
                            qual = expr.qualifier.strip() if expr.qualifier.strip() else ""
                        else:
                            qual = self._expr_to_pseudocode_simplified(expr.qualifier)
                        
                        if qual and qual not in ("<>", ""):
                            return f"{qual}.{member_name}{postfix}"
                except:
                    pass
                return f"{member_name}{postfix}"
            
            # This reference
            if isinstance(expr, This):
                return "self"
            
            # Class instance creation
            if isinstance(expr, ClassCreator):
                type_name = expr.type.name if hasattr(expr.type, 'name') else str(expr.type)
                args = []
                try:
                    if expr.arguments:
                        for arg in expr.arguments:
                            arg_str = self._expr_to_pseudocode_simplified(arg)
                            if arg_str:
                                args.append(arg_str)
                except:
                    pass
                args_str = ", ".join(args) if args else ""
                return f"new {type_name}({args_str})"
            
            # Cast expression
            if isinstance(expr, Cast):
                type_name = expr.type.name if hasattr(expr.type, 'name') else str(expr.type)
                inner = self._expr_to_pseudocode_simplified(expr.expression)
                return f"({type_name}) {inner}"
        
        except TypeError as te:
            # Handle case where isinstance fails due to Any type
            if DEBUG:
                print(f"[DEBUG] TypeError in isinstance check: {te}")
            pass
        except Exception as e:
            # Handle other exceptions gracefully - don't crash
            if DEBUG:
                print(f"[DEBUG] Other exception: {e}")
            pass
        
        # Variable / identifier
        if hasattr(expr, 'name'):
            return expr.name
        
        # Fallback for unknown expression types - try to extract meaningful info
        expr_type = type(expr).__name__
        if hasattr(expr, 'member'):
            if DEBUG:
                print(f"[DEBUG] Fallback to member extraction: {expr.member}")
            return expr.member
        
        # Last resort: return a generic description
        return f"<{expr_type}>"
    
    def _infer_method_purpose(self, method_name: str) -> str:
        """Infer the purpose of a method from its name."""
        method_lower = method_name.lower()
        
        if method_lower.startswith('get'):
            return "Get/retrieve data"
        elif method_lower.startswith('set'):
            return "Set/modify data"
        elif method_lower.startswith('is'):
            return "Check boolean condition"
        elif method_lower.startswith('init') or method_lower == '<init>':
            return "Initialize object"
        elif method_lower.startswith('create'):
            return "Create new instance"
        elif method_lower.startswith('parse'):
            return "Parse input data"
        elif method_lower.startswith('validate'):
            return "Validate input"
        elif method_lower.startswith('process'):
            return "Process data"
        elif method_lower.startswith('calculate'):
            return "Perform calculation"
        elif method_lower.startswith('execute'):
            return "Execute operation"
        elif method_lower.startswith('handle'):
            return "Handle event/action"
        elif method_lower.startswith('cancel') or method_lower.startswith('stop'):
            return "Cancel/stop operation"
        else:
            return "Perform operation"
    
    def _analyze_complexity(self, statements: List[Statement]) -> Dict[str, Any]:
        """Analyze the complexity of a code block."""
        control_flow_count = 0
        method_call_count = 0
        has_loop = False
        has_exception_handling = False
        
        for stmt in statements:
            # Safe isinstance check with try-except
            try:
                if isinstance(stmt, (IfStatement, SwitchStatement)):
                    control_flow_count += 1
                elif isinstance(stmt, (WhileStatement, ForStatement, DoWhileStatement)):
                    control_flow_count += 1
                    has_loop = True
                elif isinstance(stmt, TryStatement):
                    has_exception_handling = True
            except TypeError:
                # Handle case where type is Any from typing module
                pass
            
            if self._contains_method_call(stmt):
                method_call_count += 1
        
        high_complexity = control_flow_count >= 3 or (has_loop and control_flow_count >= 2)
        
        return {
            'control_flow_count': control_flow_count,
            'method_call_count': method_call_count,
            'has_loop': has_loop,
            'has_exception_handling': has_exception_handling,
            'high_complexity': high_complexity,
            'statement_count': len(statements)
        }
    
    def _contains_method_call(self, stmt) -> bool:
        """Check if a statement contains method calls."""
        try:
            if isinstance(stmt, StatementExpression):
                return isinstance(stmt.expression, (MethodInvocation, SuperMethodInvocation))
            if isinstance(stmt, (IfStatement, WhileStatement, ForStatement, DoWhileStatement)):
                return True  # Most control flow statements might contain method calls
        except TypeError:
            # Handle case where isinstance fails due to Any type
            pass
        return False
    
    def _method_to_pseudocode(self, method: MethodDeclaration, indent: int = 1) -> List[str]:
        """Convert a Java method declaration into pseudocode lines."""
        lines = []
        indent_str = "    " * indent
        
        # Method signature
        params = []
        for param in method.parameters:
            param_str = f"{param.name}: {param.type.name}"
            params.append(param_str)
        param_str = ", ".join(params) if params else ""
        
        return_type = method.return_type.name if method.return_type else "void"
        lines.append(f"{indent_str}function {method.name}({param_str}):")
        lines.append(f"{indent_str}    // returns: {return_type}")
        
        # Method body (if any)
        if method.body and hasattr(method.body, 'statements'):
            body_lines = self._statements_to_pseudocode(method.body.statements, indent + 1)
            lines.extend(body_lines)
        else:
            lines.append(f"{indent_str}    // (empty method)")
        
        lines.append("")  # blank line after method
        return lines
    
    def _statements_to_pseudocode(self, statements: List[Statement], indent: int) -> List[str]:
        """Recursively convert a list of AST statements to pseudocode."""
        lines = []
        indent_str = "    " * indent
        
        for stmt in statements:
            # If statement
            if isinstance(stmt, IfStatement):
                condition = self._expr_to_pseudocode(stmt.condition)
                lines.append(f"{indent_str}if {condition} then")
                # Then branch
                then_lines = self._statements_to_pseudocode([stmt.then_statement], indent + 1) if stmt.then_statement else []
                lines.extend(then_lines)
                # Else branch
                if stmt.else_statement:
                    lines.append(f"{indent_str}else")
                    else_lines = self._statements_to_pseudocode([stmt.else_statement], indent + 1)
                    lines.extend(else_lines)
            
            # While loop
            elif isinstance(stmt, WhileStatement):
                condition = self._expr_to_pseudocode(stmt.condition)
                lines.append(f"{indent_str}while {condition} do")
                body_lines = self._statements_to_pseudocode(stmt.body.statements if hasattr(stmt.body, 'statements') else [stmt.body], indent + 1)
                lines.extend(body_lines)
                lines.append(f"{indent_str}end while")
            
            # For loop
            elif isinstance(stmt, ForStatement):
                # Simplify for loop: for(init; condition; update)
                init = self._expr_to_pseudocode(stmt.control.init) if stmt.control.init else ""
                condition = self._expr_to_pseudocode(stmt.control.condition) if stmt.control.condition else ""
                update = self._expr_to_pseudocode(stmt.control.update) if stmt.control.update else ""
                lines.append(f"{indent_str}for {init} while {condition} do {update}")
                body_lines = self._statements_to_pseudocode(stmt.body.statements if hasattr(stmt.body, 'statements') else [stmt.body], indent + 1)
                lines.extend(body_lines)
                lines.append(f"{indent_str}end for")
            
            # Do-while loop
            elif isinstance(stmt, DoWhileStatement):
                condition = self._expr_to_pseudocode(stmt.condition)
                lines.append(f"{indent_str}do")
                body_lines = self._statements_to_pseudocode(stmt.body.statements if hasattr(stmt.body, 'statements') else [stmt.body], indent + 1)
                lines.extend(body_lines)
                lines.append(f"{indent_str}while {condition}")
            
            # Try-Catch
            elif isinstance(stmt, TryStatement):
                lines.append(f"{indent_str}try")
                try_lines = self._statements_to_pseudocode(stmt.block.statements if hasattr(stmt.block, 'statements') else [], indent + 1)
                lines.extend(try_lines)
                for catch in stmt.catches:
                    lines.append(f"{indent_str}catch ({catch.parameter.type.name} {catch.parameter.name})")
                    catch_lines = self._statements_to_pseudocode(catch.block.statements if hasattr(catch.block, 'statements') else [], indent + 1)
                    lines.extend(catch_lines)
                if stmt.finally_block:
                    lines.append(f"{indent_str}finally")
                    finally_lines = self._statements_to_pseudocode(stmt.finally_block.statements if hasattr(stmt.finally_block, 'statements') else [], indent + 1)
                    lines.extend(finally_lines)
            
            # Return statement
            elif isinstance(stmt, ReturnStatement):
                if stmt.expression:
                    expr = self._expr_to_pseudocode(stmt.expression)
                    lines.append(f"{indent_str}return {expr}")
                else:
                    lines.append(f"{indent_str}return")
            
            # Throw statement
            elif isinstance(stmt, ThrowStatement):
                expr = self._expr_to_pseudocode(stmt.expression)
                lines.append(f"{indent_str}throw {expr}")
            
            # Assert statement
            elif isinstance(stmt, AssertStatement):
                condition = self._expr_to_pseudocode(stmt.condition)
                lines.append(f"{indent_str}assert {condition}")
            
            # Switch statement
            elif isinstance(stmt, SwitchStatement):
                selector = self._expr_to_pseudocode(stmt.selector)
                lines.append(f"{indent_str}switch {selector}")
                for case in stmt.cases:
                    if case.case:
                        case_expr = self._expr_to_pseudocode(case.case[0])
                        lines.append(f"{indent_str}    case {case_expr}:")
                    else:
                        lines.append(f"{indent_str}    default:")
                    case_lines = self._statements_to_pseudocode(case.statements, indent + 2)
                    lines.extend(case_lines)
                lines.append(f"{indent_str}end switch")
            
            # Local variable declaration
            elif isinstance(stmt, LocalVariableDeclaration):
                for declarator in stmt.declarators:
                    if declarator.initializer:
                        init_expr = self._expr_to_pseudocode(declarator.initializer)
                        lines.append(f"{indent_str}let {declarator.name}: {stmt.type.name} = {init_expr}")
                    else:
                        lines.append(f"{indent_str}let {declarator.name}: {stmt.type.name}")
            
            # Expression statement (method call, assignment, etc.)
            elif isinstance(stmt, StatementExpression):
                expr_str = self._expr_to_pseudocode(stmt.expression)
                if expr_str:
                    lines.append(f"{indent_str}{expr_str}")
            
            # Block statement (nested block)
            elif isinstance(stmt, BlockStatement):
                block_lines = self._statements_to_pseudocode(stmt.statements, indent)
                lines.extend(block_lines)
            
            # Default: try to stringify
            else:
                # Fallback for unknown statement types
                lines.append(f"{indent_str}// {str(stmt)[:80]}")
        
        return lines
    
    def _expr_to_pseudocode(self, expr) -> str:
        """Convert an AST expression into a readable pseudocode string."""
        if expr is None:
            return ""
        
        # Literals (numbers, strings, booleans, null)
        if isinstance(expr, Literal):
            return str(expr.value)
        
        # Binary operations (a + b, a == b, etc.)
        if isinstance(expr, BinaryOperation):
            left = self._expr_to_pseudocode(expr.operandl)
            right = self._expr_to_pseudocode(expr.operandr)
            op = expr.operator
            # Map Java operators to pseudocode-friendly symbols
            op_map = {
                "==": "equals",
                "!=": "not equals",
                "&&": "and",
                "||": "or",
                "+": "+",
                "-": "-",
                "*": "*",
                "/": "/",
                "%": "mod",
                "<": "<",
                "<=": "<=",
                ">": ">",
                ">=": ">=",
                "=": "=",  # assignment
            }
            pseud_op = op_map.get(op, op)
            return f"{left} {pseud_op} {right}"
        
        # Unary operations (!flag, -value)
        if isinstance(expr, UnaryOperation):
            operand = self._expr_to_pseudocode(expr.operand)
            op = expr.operator
            if op == "!":
                return f"not {operand}"
            elif op == "-":
                return f"-{operand}"
            else:
                return f"{op}{operand}"
        
        # Ternary expression (cond ? a : b)
        if isinstance(expr, TernaryExpression):
            cond = self._expr_to_pseudocode(expr.condition)
            true_val = self._expr_to_pseudocode(expr.true)
            false_val = self._expr_to_pseudocode(expr.false)
            return f"if {cond} then {true_val} else {false_val}"
        
        # Assignment
        if isinstance(expr, Assignment):
            left = self._expr_to_pseudocode(expr.expressionl)
            right = self._expr_to_pseudocode(expr.value)
            return f"{left} ← {right}"
        
        # Method invocation
        if isinstance(expr, MethodInvocation):
            if expr.qualifier:
                qual = self._expr_to_pseudocode(expr.qualifier)
                method_name = expr.member
            else:
                qual = ""
                method_name = expr.member
            args = [self._expr_to_pseudocode(arg) for arg in expr.arguments]
            args_str = ", ".join(args) if args else ""
            if qual:
                return f"{qual}.{method_name}({args_str})"
            else:
                return f"{method_name}({args_str})"
        
        # Member reference (obj.field)
        if isinstance(expr, MemberReference):
            qual = self._expr_to_pseudocode(expr.qualifier)
            return f"{qual}.{expr.member}"
        
        # This reference
        if isinstance(expr, This):
            return "self"
        
        # Class instance creation (new)
        if isinstance(expr, ClassCreator):
            type_name = expr.type.name
            args = [self._expr_to_pseudocode(arg) for arg in expr.arguments]
            args_str = ", ".join(args) if args else ""
            return f"new {type_name}({args_str})"
        
        # Array creation
        if isinstance(expr, ArrayCreator):
            type_name = expr.type.name
            dims = [self._expr_to_pseudocode(d) for d in expr.dimensions] if expr.dimensions else []
            dims_str = "][".join(dims)
            return f"new {type_name}[{dims_str}]"
        
        # Cast expression
        if isinstance(expr, Cast):
            type_name = expr.type.name
            inner = self._expr_to_pseudocode(expr.expression)
            return f"({type_name}) {inner}"
        
        # Instanceof
        if isinstance(expr, InstanceOf):
            obj = self._expr_to_pseudocode(expr.expression)
            type_name = expr.type.name
            return f"{obj} instanceof {type_name}"
        
        # Variable / identifier
        if hasattr(expr, 'name'):
            return expr.name
        
        # Fallback: convert to string
        return str(expr)
    
    # ========== FUNCTION EXTRACTION (AST version) ==========
    
    def _extract_functions_ast(self, code: str) -> List[PseudoFunction]:
        """Extract functions using AST parsing."""
        try:
            tree = javalang.parse.parse(code)
        except Exception:
            return []
        
        functions = []
        for path, node in tree:
            if isinstance(node, MethodDeclaration):
                parameters = [f"{p.name}: {p.type.name}" for p in node.parameters]
                body_lines = []
                if node.body and hasattr(node.body, 'statements'):
                    body_lines = self._statements_to_pseudocode(node.body.statements, 0)
                
                pseudo_func = PseudoFunction(
                    name=node.name,
                    parameters=parameters,
                    return_type=node.return_type.name if node.return_type else "void",
                    description=f"Method: {node.name}",
                    body=body_lines,
                    complexity=self._estimate_complexity_ast(node)
                )
                functions.append(pseudo_func)
        
        return functions
    
    def _estimate_complexity_ast(self, method: MethodDeclaration) -> str:
        """Estimate complexity from AST."""
        if not method.body or not hasattr(method.body, 'statements'):
            return "low"
        complexity_count = 0
        # Count control flow statements
        for stmt in method.body.statements:
            if isinstance(stmt, (IfStatement, WhileStatement, ForStatement, DoWhileStatement, SwitchStatement, TryStatement)):
                complexity_count += 1
        if complexity_count >= 5:
            return "high"
        elif complexity_count >= 2:
            return "medium"
        else:
            return "low"
    
    def _generate_summary_ast(self, code: str) -> str:
        """Generate a summary using AST."""
        try:
            tree = javalang.parse.parse(code)
        except Exception:
            return self._generate_summary_fallback(code)
        
        functions = self._extract_functions_ast(code)
        lines = code.split('\n')
        non_comment_lines = [l for l in lines if l.strip() and not l.strip().startswith("//")]
        
        summary = f"""
Code Analysis Summary
=====================
Total Lines: {len(lines)}
Actual Code Lines: {len(non_comment_lines)}
Functions Found: {len(functions)}

Functions:
"""
        for func in functions[:10]:
            summary += f"  - {func.name}({', '.join(func.parameters)}) -> {func.return_type} [{func.complexity}]\n"
        
        if len(functions) > 10:
            summary += f"  ... and {len(functions) - 10} more functions\n"
        
        return summary
    
    # ========== FALLBACK PARSERS (Regex-based, original behavior) ==========
    
    def _generate_from_java_fallback(self, code: str) -> str:
        """Fallback: regex-based Java parsing (original logic)."""
        lines = code.split('\n')
        pseudocode_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith("//"):
                pseudocode_lines.append(line)
                i += 1
                continue
            
            if line.startswith("class ") or line.startswith("public class"):
                class_name = self._extract_class_name(line)
                pseudocode_lines.append(f"class {class_name}:")
                pseudocode_lines.append("    '''Class definition'''")
                i += 1
                continue
            
            if "(" in line and ")" in line and "{" in line:
                method_info = self._extract_method_info(line)
                if method_info:
                    pseudocode_lines.extend(self._create_method_pseudocode(method_info))
                i += 1
                continue
            
            if line and not line.startswith("}"):
                pseudo_line = self._simplify_statement(line)
                if pseudo_line:
                    pseudocode_lines.append(pseudo_line)
            
            i += 1
        
        return "\n".join(pseudocode_lines)
    
    def _generate_from_kotlin_fallback(self, code: str) -> str:
        """Fallback for Kotlin (same as Java fallback)."""
        return self._generate_from_java_fallback(code)
    
    def _generate_from_smali(self, code: str) -> str:
        """Generate pseudocode from Smali bytecode."""
        lines = code.split('\n')
        pseudocode_lines = ["// Smali Bytecode Analysis"]
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith(".method"):
                method_name = self._extract_smali_method(line)
                pseudocode_lines.append(f"\nmethod {method_name}:")
                i += 1
                continue
            if line.startswith("invoke-"):
                invoke_type = self._parse_smali_invoke(line)
                if invoke_type:
                    pseudocode_lines.append(f"    {invoke_type}")
            if line.startswith("return"):
                pseudocode_lines.append(f"    {line}")
            i += 1
        
        return "\n".join(pseudocode_lines)
    
    def _generate_generic(self, code: str) -> str:
        """Generate generic pseudocode for unknown code type."""
        lines = code.split('\n')
        pseudocode_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            pseudo_line = self._simplify_statement(stripped)
            if pseudo_line:
                pseudocode_lines.append(pseudo_line)
        return "\n".join(pseudocode_lines)
    
    def _extract_class_name(self, line: str) -> str:
        match = re.search(r"class\s+(\w+)", line, re.IGNORECASE)
        return match.group(1) if match else "UnknownClass"
    
    def _extract_method_info(self, line: str) -> Optional[Dict]:
        match = re.search(r"(?:public|private|protected|static)?\s*(\w+)\s+(\w+)\s*\(([^)]*)\)", line)
        if match:
            return {
                "return_type": match.group(1),
                "name": match.group(2),
                "parameters": [p.strip() for p in match.group(3).split(',') if p.strip()]
            }
        return None
    
    def _create_method_pseudocode(self, method_info: Dict) -> List[str]:
        pseudocode = []
        pseudocode.append("")
        pseudocode.append(f"function {method_info['name']}({', '.join(method_info['parameters'])}):")
        pseudocode.append(f"    '''Returns: {method_info['return_type']}'''")
        pseudocode.append("    // Implementation")
        return pseudocode
    
    def _extract_smali_method(self, line: str) -> str:
        signature = re.sub(r"^\.method\s+", "", line.strip())
        signature = re.sub(
            r"\b(public|private|protected|static|final|synthetic|constructor|abstract|native|bridge|declared-synchronized|synchronized|varargs|strictfp)\b",
            "",
            signature,
        ).strip()
        match = re.search(r"([<>\w$-]+)\s*\(", signature)
        return match.group(1) if match else "unknown_method"
    
    def _parse_smali_invoke(self, line: str) -> Optional[str]:
        if "invoke-static" in line:
            return "call static function"
        elif "invoke-virtual" in line:
            return "call instance method"
        elif "invoke-direct" in line:
            return "call private method"
        return None
    
    def _simplify_statement(self, line: str) -> str:
        if not line:
            return ""
        simplified = line
        for pattern, replacement in self.SIMPLIFICATION_RULES.items():
            simplified = re.sub(pattern, replacement, simplified)
        simplified = simplified.rstrip(';{')
        simplified = self._simplify_patterns(simplified)
        return simplified
    
    def _simplify_patterns(self, line: str) -> str:
        line = re.sub(r"(\w+)\s+(\w+)\s*=\s*", r"set \2 = ", line)
        line = re.sub(r"\.get\(", r".access(", line)
        line = re.sub(r"\.put\(", r".store(", line)
        line = re.sub(r"==\s*true", "is true", line)
        line = re.sub(r"==\s*false", "is false", line)
        line = re.sub(r"==\s*null", "is null", line)
        line = re.sub(r"!=\s*null", "is not null", line)
        return line
    
    # Fallback function extraction
    def _extract_functions_fallback(self, code: str) -> List[PseudoFunction]:
        functions = []
        lines = code.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if "(" in line and ")" in line and "{" in line:
                method_info = self._extract_method_info(line)
                if method_info:
                    body_lines = []
                    brace_count = 1
                    j = i + 1
                    while j < len(lines) and brace_count > 0:
                        body_line = lines[j].strip()
                        brace_count += body_line.count('{') - body_line.count('}')
                        if brace_count > 0:
                            body_lines.append(self._simplify_statement(body_line))
                        j += 1
                    pseudo_func = PseudoFunction(
                        name=method_info['name'],
                        parameters=method_info['parameters'],
                        return_type=method_info['return_type'],
                        description=f"Method: {method_info['name']}",
                        body=body_lines,
                        complexity=self._estimate_complexity(body_lines)
                    )
                    functions.append(pseudo_func)
                    i = j
                    continue
            i += 1
        return functions
    
    def _estimate_complexity(self, body_lines: List[str]) -> str:
        if not body_lines:
            return "low"
        complexity_indicators = 0
        for line in body_lines:
            if any(kw in line.lower() for kw in ["if", "for", "while", "switch"]):
                complexity_indicators += 1
            if "try" in line.lower() or "catch" in line.lower():
                complexity_indicators += 1
        if complexity_indicators >= 3:
            return "high"
        elif complexity_indicators >= 1:
            return "medium"
        else:
            return "low"
    
    def _generate_summary_fallback(self, code: str) -> str:
        lines = code.split('\n')
        non_comment_lines = [l for l in lines if l.strip() and not l.strip().startswith("//")]
        functions = self._extract_functions_fallback(code)
        
        summary = f"""
Code Analysis Summary
=====================
Total Lines: {len(lines)}
Actual Code Lines: {len(non_comment_lines)}
Functions Found: {len(functions)}

Functions:
"""
        for func in functions[:10]:
            summary += f"  - {func.name}({', '.join(func.parameters)}) -> {func.return_type} [{func.complexity}]\n"
        
        if len(functions) > 10:
            summary += f"  ... and {len(functions) - 10} more functions\n"
        
        return summary
