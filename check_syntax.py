import ast, sys
try:
    with open("app.py", encoding="utf-8") as f:
        src = f.read()
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError at line {e.lineno}: {e.msg}")
    print(f"  -> {e.text}")
