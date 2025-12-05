from pathlib import Path
from typing import List, Generator, Set

class FileSystemWalker:
    """
    Adapter encargado de interactuar con el Disco Duro.
    Aplica filtros de seguridad y recorre directorios eficientemente.
    """
    
    # Extensiones que sabemos que son binarias o irrelevantes
    BINARY_EXTENSIONS: Set[str] = {
        '.pyc', '.png', '.jpg', '.jpeg', '.gif', '.exe', 
        '.dll', '.so', '.bin', '.zip', '.tar', '.gz', '.pdf'
    }

    def __init__(self, ignore_dirs: List[str]):
        self.ignore_dirs = set(ignore_dirs)

    def _is_scannable(self, path: Path) -> bool:
        """Filtro de seguridad: ignora ocultos, binarios y archivos gigantes."""
        # 1. Ignorar archivos ocultos
        if path.name.startswith("."):
            return False
            
        # 2. Ignorar extensiones binarias
        if path.suffix.lower() in self.BINARY_EXTENSIONS:
            return False

        # 3. Check de tamaño (Max 1MB) - Protección contra DoS
        try:
            if path.stat().st_size > 1_000_000: 
                return False
        except OSError:
            return False 
            
        return True

    def _is_ignored_dir(self, path: Path) -> bool:
        """Verifica si la carpeta actual debe ser ignorada."""
        return path.name in self.ignore_dirs

    def get_files(self, root_path: Path) -> Generator[Path, None, None]:
        """
        Generador (yield) que entrega archivos seguros uno a uno.
        """
        if root_path.is_file():
            if self._is_scannable(root_path):
                yield root_path
            return

        # rglog("*") es recursivo, pero implementamos un walk manual para
        # poder podar (prune) directorios ignorados eficientemente.
        for path in root_path.rglob("*"):
            # Si es un directorio y está en la lista negra, no entramos (esto es simplificado)
            # Nota: rglob no permite "podar" el árbol fácilmente, pero filtramos resultados.
            if any(ignored in path.parts for ignored in self.ignore_dirs):
                continue
            
            if path.is_file() and self._is_scannable(path):
                yield path