import ast
import glob

def check_file(filename):
    with open(filename, "r") as f:
        source = f.read()
    
    try:
        tree = ast.parse(source)
    except Exception as e:
        return
        
    class BlockVisitor(ast.NodeVisitor):
        def visit_With(self, node):
            is_db_as_user = False
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    func = item.context_expr.func
                    if isinstance(func, ast.Attribute) and func.attr == "as_user":
                        is_db_as_user = True
            
            if is_db_as_user:
                saw_commit = False
                for stmt in node.body:
                    # check if stmt contains commit
                    commit_in_stmt = False
                    for subnode in ast.walk(stmt):
                        if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Attribute):
                            if subnode.func.attr == "commit":
                                commit_in_stmt = True
                    
                    if commit_in_stmt:
                        saw_commit = True
                    elif saw_commit:
                        # check if stmt contains execute
                        for subnode in ast.walk(stmt):
                            if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Attribute):
                                if subnode.func.attr == "execute":
                                    print(f"{filename}: execute after commit!")
                                    return
            self.generic_visit(node)

    BlockVisitor().visit(tree)

for filename in glob.glob("app/**/*.py", recursive=True):
    check_file(filename)
