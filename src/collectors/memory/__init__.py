"""
Memory Analysis Modules

Provides analyzers for Windows memory artifacts:
- pagefile.sys analysis
- hiberfil.sys analysis
"""

try:
    from .pagefile_analyzer import PagefileAnalyzer
    from .hiberfil_analyzer import HiberfilAnalyzer
    MEMORY_ANALYZER_AVAILABLE = True
except ImportError as e:
    MEMORY_ANALYZER_AVAILABLE = False
    PagefileAnalyzer = None
    HiberfilAnalyzer = None
    _import_error = str(e)

__all__ = [
    'PagefileAnalyzer',
    'HiberfilAnalyzer',
    'MEMORY_ANALYZER_AVAILABLE'
]
