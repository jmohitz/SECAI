import requests
import streamlit as st
from langchain_community.llms import OpenAI

# Set up API keys
GOOGLE_API_KEY = "AIzaSyDBQoupcjAx0FQpfPyvCdka07kFNGaMu64"  # Replace with your Google API key
GOOGLE_CSE_ID = "741f54c5d57bb496d"    # Replace with your Google Custom Search Engine ID

# Perform web search using Google Custom Search API
def web_search(query: str) -> dict:
    """
    Perform a web search using Google Custom Search API.
    """
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "q": query,
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CSE_ID,
    }
    try:
        response = requests.get(url, params=params, timeout=30)  # 30-second timeout
        return response.json()
    except requests.Timeout:
        st.error("Web search timed out. Please try again.")
        return {}

# Generate a response using OpenAI GPT
def generate_response(query: str, context: str) -> str:
    """
    Generate a response using OpenAI GPT based on the combined context.
    """
    llm = OpenAI(openai_api_key="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", temperature=0.7)  # Replace with your OpenAI API key
    prompt = f"""Question: I am going to give you a code snippet below which is a error/vulnerability recognised by cognicrypt and also the code snippet was given to google for google search, so that you can get more context for it, and now the user has clicked a button called ai fix which means the code is now given to you below  with search data and you have to provide a line solution for it and also you have to explain why you have chosen this solution and also give cve/cwe id related to it and also give references. The below line is the code error:
{query}\n\nContext: This is the web search result from Google Custom Search API:
 \n{context}\n\n Answer: 
 
 Use this template to give the output like I said:

error code :

Solution: give alternative secure code for error code

explanation:  detailed explanation in about 100-150 words

Cve id: give all relevant id if found otherwise do not give any

Cwe id: give all relevant id if found otherwise do not give any

references: try not to hallucinate and give real references and you can also you the search data of Google Custom Search API to give references and give upto 3 references"""
    response = llm(prompt)
    return response

# Build the Streamlit app
def main():
    st.title("SECAI - AI FIX")

    # User input
    query = st.text_input("Enter your query:")

    if query:
        st.write("Performing web search...")
        web_results = web_search(query)
        st.write("Web search complete.")

        # Extract relevant information from web search
        web_context = ""
        if "items" in web_results:
            for result in web_results["items"]:
                web_context += f"{result['title']}\n{result['snippet']}\n\n"

        st.write("Generating response using OpenAI GPT...")
        response = generate_response(query, web_context)
        st.write("Response generated.")

        # Display the response
        st.write("### Response")
        st.write(response)

if __name__ == "__main__":
    main()


openai_api_key = "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"  # Your OpenAI API key
google_api_key = "AIzaSyDBQoupcjAx0FQpfPyvCdka07kFNGaMu64"    # Your Google API key
google_cse_id  = "741f54c5d57bb496d"         # Your Google CSE ID