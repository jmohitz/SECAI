from langchain_google_genai import ChatGoogleGenerativeAI
from .base import BaseLLM

class GeminiHandler(BaseLLM):
    def __init__(self, model = "gemini-2.0-flash",**kwargs):
        super().__init__(ChatGoogleGenerativeAI(model=model,**kwargs))
