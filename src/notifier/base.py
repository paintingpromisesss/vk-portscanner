from abc import ABC, abstractmethod
from typing import List

from src.models.schemas import PortChange

class BaseNotifier(ABC):
    @abstractmethod
    async def notify(self, changes: List[PortChange]) -> bool:
        pass
