import time
import asyncio
import logging
import uvicorn
import sys
import os
from fastapi import FastAPI, Request
from multiprocessing import Process, Queue

# --- IMPORT MODULES ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from utils.paths import setup_sys_path
setup_sys_path()

# Import logic
from inference import core_logic as wa_logic

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="ML Listener API")
flow_buffer = []
WINDOW_INTERVAL = 10 

# Queue small to maintain realtime processing
processing_queue = Queue(maxsize=3) 

def logic_worker_process(queue: Queue, window_interval: int):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [WORKER] %(message)s")
    logging.info("Worker Process Started.")
    
    while True:
        try:
            snapshot = queue.get()
            wa_logic.process_window_data_logic(snapshot, window_interval)
        except Exception as e:
            logging.error(f"Worker Critical Error: {e}")

@app.post("/ingest_flow")
async def ingest_flow(request: Request):
    try:
        payload = await request.json()
        if isinstance(payload, dict) and "flows" in payload:
            payload = payload["flows"][0]
            
        label, conf = wa_logic.predict_single_flow(payload)
        src, dst, port, proto = wa_logic.extract_flow_metadata(payload)
        
        flow_buffer.append({
            "timestamp": int(time.time()),
            "src_ip": src, "dst_ip": dst, "dst_port": port, "protocol": proto,
            "primary_label": label, "confidence": conf
        })
        
        return {"status": "ok", "label": label, "confidence": conf}
        
    except Exception as e:
        logging.error(f"Ingest Error: {e}")
        return {"status": "error", "msg": str(e)}

async def scheduler_loop():
    logging.info(f"Scheduler Started. Window Interval: {WINDOW_INTERVAL}s")
    while True:
        await asyncio.sleep(WINDOW_INTERVAL)
        
        if not flow_buffer:
            continue
        
        snapshot = flow_buffer.copy()
        flow_buffer.clear()
        
        if processing_queue.full():
            logging.warning("QUEUE FULL! Dropping oldest window to maintain realtime.")
            try:
                processing_queue.get_nowait()
            except:
                pass
        
        processing_queue.put(snapshot)
        logging.info(f"Pushed {len(snapshot)} flows to worker. Queue size: {processing_queue.qsize()}")

@app.on_event("startup")
async def startup_event():
    p = Process(target=logic_worker_process, args=(processing_queue, WINDOW_INTERVAL))
    p.daemon = True 
    p.start()
    
    asyncio.create_task(scheduler_loop())
    logging.info("Listener is ready.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)