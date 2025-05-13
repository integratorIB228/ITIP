from fastapi import FastAPI, File, UploadFile
import pandas as pd
import joblib
from io import BytesIO

app = FastAPI()

# Загрузка обученной модели
model_path = "E:\Мои документы\Desktop\Уроки\Python\ИТИП\laptop_price_model.pkl"
model = joblib.load(model_path)

@app.post("/predict/")
async def predict(file: UploadFile = File(...)):
    content = await file.read()
    df = pd.read_csv(BytesIO(content))
    predictions = model.predict(df)
    return {"predictions": predictions.tolist()}