import requests

headers = {
    "Auth-Key": "d632b53dc63669d34feb28d3697bf918fe1c9610a681983b"
}

response = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    headers=headers,
    data={
        "query": "get_info",
        "hash": "BEA719D051CA9486DCBFBD960A8A58A8657202DE6D01B42A672EFCAD76CB3070"
    }
)

print(response.status_code)
print(response.json())
