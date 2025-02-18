import requests
import streamlit as st

SERPAPI_API_KEY = "your-serpapi-key"  # Replace with your key

def web_search(query: str) -> dict:
    """
    Perform a web search using SerpAPI.
    """
    url = "https://serpapi.com/search.json"
    params = {
        "q": query,
        "api_key": SERPAPI_API_KEY,
    }
    try:
        response = requests.get(url, params=params, timeout=10)  # 10-second timeout
        return response.json()
    except requests.Timeout:
        st.error("Web search timed out. Please try again.")
        return {}
