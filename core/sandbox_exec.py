import sys
import io
import contextlib
import traceback
import builtins # REQUIRED to allow imports and standard functions

class CodeSandbox:
    def execute(self, code_snippet):
        """
        Executes Python code and captures both STDOUT and STDERR.
        Now allows imports and complex logic for better simulation.
        """
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        # 1. FIX INDENTATION ISSUES
        # Convert all tabs to 4 spaces to prevent "IndentationError" from web inputs
        if code_snippet:
            code_snippet = code_snippet.replace('\t', '    ')

        # 2. ENABLE FULL PYTHON CAPABILITIES
        # For a honeypot, we want to allow the attacker to run imports 
        # so we can see what they are trying to do.
        sandbox_env = {
            "__builtins__": builtins,  # Allows import, open, etc.
            "__name__": "__main__"
        }
        
        try:
            # Capture standard output and errors
            with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                exec(code_snippet, sandbox_env)
            
            output = stdout_capture.getvalue()
            errors = stderr_capture.getvalue()
            
            # Combine output (Show errors if any occurred)
            if errors:
                return f"{output}\n[STDERR]\n{errors}" if output else f"[EXECUTION ERROR]\n{errors}"
            
            return output if output else "[Code executed successfully. No output.]"
            
        except Exception:
            # Capture syntax errors, import errors, or runtime crashes
            return f"[RUNTIME EXCEPTION]\n{traceback.format_exc()}"
        finally:
            stdout_capture.close()
            stderr_capture.close()