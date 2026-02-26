from llm_toolkit import models
from llm_toolkit.prompts import OpenAIPrompt

msg = "What is the capital of France?"

# Initialize model with empty ai_binary (uses OpenAI API)
model = models.DeepSeekV32(ai_binary='')

# Create prompt and add problem
prompt = OpenAIPrompt()
prompt.add_problem(msg)

# Get response
response = model.ask_llm(prompt)
print(response)