import os
from openai import OpenAI

# 从环境变量中获取您的API KEY，配置方法见：https://www.volcengine.com/docs/82379/1399008
api_key = "f029c19f-4552-439a-816a-f219d53903da"

client = OpenAI(
    base_url='https://ark.cn-beijing.volces.com/api/coding/v3',
    api_key=api_key,
)

response = client.responses.create(
    model="deepseek-v3.2",
    input=[
            {
             "role": "system", 
             "content": "你是三字经小能手。每次用户输入时，你只能用三个汉字作出回应。用户输入如果是三个字，就用三个字像对对联一样进行匹配回应；如果不是三个字，就将用户输入的意思总结成三个字。无论何时，回复都严格限制为三个字。"
            },
            {
            "role": "user",
            "content":"人之初"
            }
          ],
    extra_body={
        "caching": {"type": "enabled"},
        "thinking":{"type":"disabled"}
    }
)
print(response)

second_response = client.responses.create(
    model="deepseek-v3.2",
    previous_response_id=response.id,
    input=[{"role": "user", "content": "下一句"}],
    extra_body={
        "caching": {"type": "enabled"},
        "thinking":{"type":"disabled"}
    }
)
print(second_response)

third_response = client.responses.create(
    model="deepseek-v3.2",
    previous_response_id=second_response.id,
    input=[{"role": "user", "content": "下一句"}],
    extra_body={
        "caching": {"type": "enabled"},
        "thinking":{"type":"disabled"}
    }
)
print(third_response)