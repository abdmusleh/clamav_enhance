# app/main.py
import os
import logging
from fastapi import FastAPI, File, UploadFile, HTTPException

from analyzer import analyze_sample
from rulegen import generate_rules

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()

@app.post("/scan/")
async def scan(file: UploadFile = File(...)):
    temp_storage_dir = os.path.join("/tmp", "amds_fastapi_temp_samples")
    os.makedirs(temp_storage_dir, exist_ok=True)

    filepath = os.path.join(temp_storage_dir, os.path.basename(file.filename))

    try:
        logging.info(f"Receiving file: {file.filename}")
        contents = await file.read()
        with open(filepath, "wb") as f:
            f.write(contents)
        logging.info(f"File saved to: {filepath}")

        features = analyze_sample(filepath)
        
        # Defensive check: Ensure generate_rules always returns a list
        raw_rules = generate_rules(features, file.filename)
        rules_to_return = raw_rules if isinstance(raw_rules, list) else []
        
        return {"rules": rules_to_return}

    except Exception as e:
        logging.error(f"Unhandled exception during scan of {file.filename}: {e}", exc_info=True)

        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                logging.info(f"Cleaned up temporary file: {filepath}")
            except OSError as rm_e:
                logging.warning(f"Failed to remove temporary file {filepath}: {rm_e}")

        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal Server Error",
                "message": f"An unhandled error occurred during processing of {file.filename}",
                "exception_type": type(e).__name__
            }
        )
    finally:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                logging.info(f"Cleaned up temporary file: {filepath}")
            except OSError as rm_e:
                logging.warning(f"Failed to remove temporary file {filepath}: {rm_e}")
