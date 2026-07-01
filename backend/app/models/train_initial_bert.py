import json
import numpy as np
from pathlib import Path

import torch
from torch.nn import CrossEntropyLoss

from datasets import Dataset
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support


DATASET_DIR = Path("app/models/bert_ready")
MODEL_DIR   = Path("app/models/bert_model")
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def load_jsonl(path: Path) -> list:
    if not path.exists():
        raise FileNotFoundError(f"No se encontró el archivo: {path}")
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records

train_data = load_jsonl(DATASET_DIR / "train.jsonl")
val_data   = load_jsonl(DATASET_DIR / "val.jsonl")
test_data  = load_jsonl(DATASET_DIR / "test.jsonl")

train_ds = Dataset.from_list(train_data)
val_ds   = Dataset.from_list(val_data)
test_ds  = Dataset.from_list(test_data)

print(f"Train: {len(train_ds)} | Val: {len(val_ds)} | Test: {len(test_ds)}")


def compute_class_weights(dataset: Dataset, num_labels: int = 3) -> torch.Tensor:
    counts = [0] * num_labels
    for item in dataset:
        counts[item["label"]] += 1
    total = sum(counts)
    # peso inversamente proporcional a la frecuencia
    weights = [total / (num_labels * c) if c > 0 else 1.0 for c in counts]
    print(f"Distribución labels: {counts} → pesos: {[round(w,3) for w in weights]}")
    return torch.tensor(weights, dtype=torch.float)

class_weights = compute_class_weights(train_ds)


tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

def tokenize(batch):
    return tokenizer(
        batch["text"],
        truncation=True,
        padding="max_length",
        max_length=512
    )

train_ds = train_ds.map(tokenize, batched=True)
val_ds   = val_ds.map(tokenize, batched=True)
test_ds  = test_ds.map(tokenize, batched=True)

train_ds = train_ds.rename_column("label", "labels")
val_ds   = val_ds.rename_column("label", "labels")
test_ds  = test_ds.rename_column("label", "labels")

cols = ["input_ids", "attention_mask", "labels"]
train_ds.set_format("torch", columns=cols)
val_ds.set_format("torch",   columns=cols)
test_ds.set_format("torch",  columns=cols)


model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased",
    num_labels=3
)


class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels  = inputs.get("labels")
        outputs = model(**inputs)
        logits  = outputs.get("logits")
        weights = class_weights.to(logits.device)
        loss    = CrossEntropyLoss(weight=weights)(logits, labels)
        return (loss, outputs) if return_outputs else loss


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="weighted", zero_division=0
    )
    acc = accuracy_score(labels, preds)

    return {
        "accuracy":  round(acc, 4),
        "f1":        round(f1, 4),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
    }


training_args = TrainingArguments(
    output_dir            = "bert_output",
    eval_strategy         = "epoch",
    save_strategy         = "epoch",
    num_train_epochs      = 5,
    per_device_train_batch_size = 8,
    per_device_eval_batch_size  = 8,
    learning_rate         = 2e-5,
    weight_decay          = 0.01,
    warmup_ratio          = 0.1,
    lr_scheduler_type     = "cosine",
    logging_steps         = 50,
    load_best_model_at_end= True,
    metric_for_best_model = "f1",
    greater_is_better     = True,
    seed                  = 42,
    data_seed             = 42,
)

trainer = WeightedTrainer(
    model           = model,
    args            = training_args,
    train_dataset   = train_ds,
    eval_dataset    = val_ds,
    compute_metrics = compute_metrics,
    callbacks       = [EarlyStoppingCallback(early_stopping_patience=2)],
)

trainer.train()


print("\n=== Evaluación en test set ===")
results = trainer.evaluate(test_ds)
for k, v in results.items():
    print(f"  {k}: {v}")


model.save_pretrained(MODEL_DIR)
tokenizer.save_pretrained(MODEL_DIR)

print(f"\nModelo DistilBERT entrenado y guardado en: {MODEL_DIR}")