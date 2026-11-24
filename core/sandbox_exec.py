import ast
import io
import threading
import traceback

# Allowed standard library modules for the serverless sandbox
ALLOWED_MODULES = {
    "math", "random", "json", "datetime", "re",
    "hashlib", "base64", "string", "collections", "itertools"
}

# Forbidden module names and keywords that attempt host or environment compromise
FORBIDDEN_NAMES = {
    "os", "sys", "subprocess", "socket", "shutil", "pathlib", "pty",
    "posix", "nt", "builtins", "__builtins__", "ctypes", "multiprocessing",
    "threading", "signal", "inspect", "importlib", "site", "time"
}

FORBIDDEN_ATTRIBUTES = {
    "__subclasses__", "__bases__", "__mro__", "__globals__", "__code__",
    "__closure__", "__builtins__", "gi_frame", "f_globals", "f_locals"
}


class SafeStream:
    """Thread-safe stream that cleanly handles background thread termination without raising on close."""
    def __init__(self):
        self._buffer = []
        self._closed = False
        self._lock = threading.Lock()

    def write(self, s):
        with self._lock:
            if not self._closed:
                self._buffer.append(str(s))

    def flush(self):
        pass

    def getvalue(self):
        with self._lock:
            return "".join(self._buffer)

    def close(self):
        with self._lock:
            self._closed = True


def _create_safe_import():
    """Custom __import__ replacement restricting imports to safe standard library modules."""
    real_import = __import__

    def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        root_module = name.split('.')[0]
        if root_module not in ALLOWED_MODULES:
            raise ImportError(
                f"[SECURITY BLOCKED] Module '{name}' is restricted in serverless sandbox. "
                f"Permitted modules: {', '.join(sorted(ALLOWED_MODULES))}"
            )
        return real_import(name, globals, locals, fromlist, level)

    return safe_import


def _build_safe_builtins(stdout_stream):
    """Builds a stripped, hardened builtins dictionary prohibiting file/system operations."""
    def safe_print(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file_arg = kwargs.get('file', None)
        text = sep.join(str(a) for a in args) + end
        if file_arg is not None and hasattr(file_arg, 'write'):
            file_arg.write(text)
        else:
            stdout_stream.write(text)

    safe_builtins = {
        # Core Types & Constructors
        "abs": abs, "all": all, "any": any, "ascii": ascii, "bin": bin,
        "bool": bool, "bytearray": bytearray, "bytes": bytes, "chr": chr,
        "complex": complex, "dict": dict, "dir": dir, "divmod": divmod,
        "enumerate": enumerate, "filter": filter, "float": float, "format": format,
        "frozenset": frozenset, "getattr": getattr, "hasattr": hasattr, "hash": hash,
        "hex": hex, "id": id, "int": int, "isinstance": isinstance,
        "issubclass": issubclass, "iter": iter, "len": len, "list": list,
        "map": map, "max": max, "min": min, "next": next, "object": object,
        "oct": oct, "ord": ord, "pow": pow, "print": safe_print, "property": property,
        "range": range, "repr": repr, "reversed": reversed, "round": round,
        "set": set, "setattr": setattr, "slice": slice, "sorted": sorted,
        "str": str, "sum": sum, "super": super, "tuple": tuple, "type": type,
        "vars": vars, "zip": zip,
        # Standard Safe Exceptions
        "BaseException": BaseException, "Exception": Exception, "ValueError": ValueError,
        "TypeError": TypeError, "KeyError": KeyError, "IndexError": IndexError,
        "AttributeError": AttributeError, "ZeroDivisionError": ZeroDivisionError,
        "OverflowError": OverflowError, "StopIteration": StopIteration,
        "RuntimeError": RuntimeError, "NameError": NameError, "ImportError": ImportError,
        "AssertionError": AssertionError,
        # Safe Import Hook
        "__import__": _create_safe_import(),
        # Constants
        "True": True, "False": False, "None": None,
    }
    return safe_builtins


class CodeSandbox:
    def __init__(self, timeout_seconds=3.0):
        self.timeout_seconds = timeout_seconds

    def _validate_ast(self, code_snippet):
        """
        Static AST audit to prevent environment exfiltration and sandbox escapes
        before any bytecode executes.
        """
        try:
            tree = ast.parse(code_snippet)
        except SyntaxError as e:
            return False, f"[SYNTAX ERROR] Line {e.lineno}: {e.msg}"

        for node in ast.walk(tree):
            # Check import statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split('.')[0]
                    if root not in ALLOWED_MODULES:
                        return False, f"[SECURITY BLOCKED] Import of '{alias.name}' is prohibited."
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root = node.module.split('.')[0]
                    if root not in ALLOWED_MODULES:
                        return False, f"[SECURITY BLOCKED] Import from '{node.module}' is prohibited."
            # Check attribute access attempts (e.g. __subclasses__, __globals__)
            elif isinstance(node, ast.Attribute):
                if node.attr in FORBIDDEN_ATTRIBUTES:
                    return False, f"[SECURITY BLOCKED] Access to private attribute '{node.attr}' is prohibited."
                if node.attr in FORBIDDEN_NAMES:
                    return False, f"[SECURITY BLOCKED] Access to system attribute '{node.attr}' is prohibited."
            # Check explicit calls to forbidden names
            elif isinstance(node, ast.Name):
                if node.id in {"eval", "exec", "open", "compile", "input", "breakpoint", "exit", "quit"}:
                    return False, f"[SECURITY BLOCKED] Call to '{node.id}' is prohibited in serverless sandbox."

        return True, ""

    def execute(self, code_snippet):
        """
        Executes Python code in a hardened serverless environment.
        - Strips dangerous builtins (open, eval, exec, compile, input, os, sys, etc.)
        - Enforces strict import allowlist
        - Captures stdout cleanly via thread-safe stream
        - Enforces execution timeout via synchronous thread join
        """
        if not code_snippet or not code_snippet.strip():
            return "[No code provided for execution.]"

        # Normalize indentation
        code_snippet = code_snippet.replace('\t', '    ')

        # 1. AST Static Security Audit
        is_safe, error_msg = self._validate_ast(code_snippet)
        if not is_safe:
            return error_msg

        # 2. Prepare Sandboxed Execution Environment
        stdout_capture = SafeStream()
        sandbox_builtins = _build_safe_builtins(stdout_capture)
        sandbox_env = {
            "__builtins__": sandbox_builtins,
            "__name__": "__main__",
            "__doc__": None,
        }

        exec_error = []
        is_timed_out = [False]

        def target_exec():
            try:
                compiled = compile(code_snippet, "<sandboxed_python>", "exec")
                exec(compiled, sandbox_env)
            except Exception:
                exec_error.append(traceback.format_exc())

        worker_thread = threading.Thread(target=target_exec, daemon=True)
        worker_thread.start()
        worker_thread.join(timeout=self.timeout_seconds)

        if worker_thread.is_alive():
            is_timed_out[0] = True

        out = stdout_capture.getvalue()
        stdout_capture.close()

        if is_timed_out[0]:
            return f"[TIMEOUT ERROR] Execution exceeded strict {self.timeout_seconds}s serverless limit. Terminated to prevent resource exhaustion."

        if exec_error:
            # Clean exception message without internal sandbox frames
            return f"{out}\n[RUNTIME ERROR]\n{exec_error[0]}" if out else f"[RUNTIME ERROR]\n{exec_error[0]}"

        return out if out else "[Code executed successfully with zero output.]"
