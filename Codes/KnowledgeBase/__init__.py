"""
知识库管理模块

用于构建和查看RAG知识库
"""

from .build_knowledge_base_50 import build_knowledge_base_sample
from .view_knowledge_base import view_knowledge_base

__all__ = ['build_knowledge_base_sample', 'view_knowledge_base']

