from langchain.agents import create_react_agent, AgentExecutor
from langchain_openai import ChatOpenAI
from langchain_community.tools import ShellTool

llm = ChatOpenAI(model="gpt-4o")
tools = [ShellTool()]
agent = create_react_agent(llm, tools, prompt)
