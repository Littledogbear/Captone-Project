"""
Simple script to download malware samples from MalwareBazaar.
"""

import os
import sys
import requests
import json
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SAMPLES_DIR = "samples/malwarebazaar"
METADATA_DIR = f"{SAMPLES_DIR}/metadata"
os.makedirs(SAMPLES_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)

def get_api_key():
    """Get the MalwareBazaar API key from environment variables."""
    api_key = os.environ.get('Malware_Bazzar_personal_key')
    if not api_key:
        logger.error("Error: MalwareBazaar API key not found.")
        return None
    logger.info(f"API key found (length: {len(api_key)} characters)")
    return api_key

def download_samples():
    """Download samples from MalwareBazaar."""
    url = "https://mb-api.abuse.ch/api/v1/"
    api_key = get_api_key()
    
    if not api_key:
        return False
    
    query_types = [
        {"query": "get_recent", "limit": 3},
        {"query": "get_taginfo", "tag": "ransomware", "limit": 3},
        {"query": "get_taginfo", "tag": "trojan", "limit": 3}
    ]
    
    for query_data in query_types:
        logger.info(f"Trying query: {query_data}")
        
        headers = {
            "API-KEY": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(url, data=query_data, headers=headers, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"HTTP Error: {response.status_code}")
                continue
            
            result = response.json()
            
            if result.get("query_status") == "ok":
                samples = result.get("data", [])
                logger.info(f"Successfully retrieved {len(samples)} samples")
                
                if not samples:
                    logger.warning("No samples found in API response.")
                    continue
                
                for sample in samples:
                    sha256_hash = sample.get("sha256_hash")
                    if not sha256_hash:
                        continue
                    
                    metadata_path = os.path.join(METADATA_DIR, f"{sha256_hash}.json")
                    with open(metadata_path, "w") as f:
                        json.dump(sample, f, indent=2)
                    logger.info(f"Saved metadata to {metadata_path}")
                
                return True
            else:
                logger.error(f"API Error: {result.get('query_status')}")
                continue
                
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            continue
    
    return False

if __name__ == "__main__":
    print("=== MalwareBazaar Sample Retrieval ===")
    success = download_samples()
    if success:
        print("Sample metadata download successful.")
        import glob
        metadata_files = glob.glob(f"{METADATA_DIR}/*.json")
        print(f"Downloaded metadata for {len(metadata_files)} samples:")
        for metadata_file in metadata_files[:5]:  # Show up to 5 samples
            try:
                with open(metadata_file, "r") as f:
                    sample = json.load(f)
                print(f"- {sample.get('file_name', 'Unknown')} ({sample.get('sha256_hash', 'Unknown')})")
            except:
                pass
    else:
        print("Sample download failed.")
    sys.exit(0 if success else 1)
