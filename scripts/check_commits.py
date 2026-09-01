import ast
import glob
import sys

def check_file(filename):
    with open(filename, "r") as f:
        source = f.read()
    
    try:
        tree = ast.parse(source)
    except Exception as e:
        return
        
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            # check if it is `with db.as_user(...) as conn`
            is_db_as_user = False
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    func = item.context_expr.func
                    if isinstance(func, ast.Attribute) and func.attr == "as_user":
                        is_db_as_user = True
            
            if is_db_as_user:
                # check sequence of statements
                saw_commit = False
                for stmt in node.body:
                    for subnode in ast.walk(stmt):
                        if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Attribute):
                            if subnode.func.attr == "commit":
                                saw_commit = True
                            elif subnode.func.attr == "execute" and saw_commit:
                                print(f"{filename}: execute after commit in same block!")
                                break

for filename in glob.glob("app/**/*.py", recursive=True):
    check_file(filename)
