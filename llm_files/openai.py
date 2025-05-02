from langchain_openai import ChatOpenAI
from .base import BaseLLM

class OpenAIHandler(BaseLLM):
    def __init__(self, model="gpt-4o-mini", **kwargs):
        super().__init__(ChatOpenAI(model=model,**kwargs))
