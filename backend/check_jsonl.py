import json

path = "app/models/bert_ready/train.jsonl"

with open(path, "r", encoding="utf-8") as f:
    for i, line in enumerate(f, start=1):
        try:
            json.loads(line)
        except Exception as e:
            print(f"❌ ERROR en línea {i}: {e}")
            print("Contenido:", line)
