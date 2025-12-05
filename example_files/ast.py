# prueba_ast.py

# Caso 1: Vulnerabilidad REAL
x = input("Dame codigo: ")
eval(x)  # <-- El AST debe detectar esto

# Caso 2: Falso Positivo para Regex (El AST debe IGNORAR esto)
print("No debes usar la funcion eval en tu codigo") 

# Caso 3: Comentario (El AST debe IGNORAR esto)
# TODO: Revisar si eval es necesario aqui