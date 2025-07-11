import socket
import json
import pandas as pd
import joblib
from together import Together
import os
from dotenv import load_dotenv


load_dotenv()

HOST = 'localhost'
PORT = 9999
MODEL_PATH = "anomaly_model.joblib"
CSV_FILE_PATH = "anomalies.csv"

try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    print(f"Error: Model file not found at '{MODEL_PATH}'.")
    print("Please run 'train_model.ipynb' first to generate the model file.")
    exit()

def pre_process_data(data):
    df = pd.DataFrame([data])
    #TODO 2
    encoded_df = pd.get_dummies(df, columns=['protocol'], drop_first=True, dtype=bool)
    training_columns = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']

    for col in training_columns:
        if col not in encoded_df.columns:
            encoded_df[col] = False

    return encoded_df[training_columns].values

print("Attempting to connect to the server...")
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        buffer = ""
        print("Client connected to server. Waiting for data...\n")

        while True:
            chunk = s.recv(1024).decode()
            if not chunk:
                print("Server closed the connection.")
                break
            buffer += chunk

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    print(f'Data Received: {data}')

                    #TODO 3
                    X = pre_process_data(data)

                    score = model.decision_function(X)[0]

                    #TODO 4
                    if score < 0:

                        print(f"🚨 Anomaly Detected! (Confidence Score: {score:.2f})")

                        TOGETHER_API_KEY = os.environ.get("TOGETHER_API_KEY")
                        if not TOGETHER_API_KEY:
                            llm_reply = "LLM explanation not available (API key missing)."
                        else:
                            try:
                                client = Together(api_key=TOGETHER_API_KEY)
                                user_prompt = (
                                    f"A network sensor detected an anomaly with the following data: {data}. "
                                    "Based on this data, what is the likely type of anomaly (e.g., Port Scan, Large Packet, etc.) "
                                    "and what is a possible cause? Be concise."
                                )
                                messages = [
                                    {"role": "system",
                                     "content": "You are a cybersecurity assistant. You label and explain network anomalies based on sensor data."},
                                    {"role": "user", "content": user_prompt}
                                ]
                                response = client.chat.completions.create(
                                    model="meta-llama/Llama-3-70b-chat-hf",
                                    messages=messages,
                                    stream=False,
                                )
                                llm_reply = response.choices[0].message.content.strip() if response.choices and \
                                                                                           response.choices[
                                                                                               0].message.content else "No response from LLM."
                            except Exception as e:
                                llm_reply = f"LLM call failed: {e}"

                        print(f"\n--- ANOMALY ALERT ---\n"
                              f"Confidence Score: {score:.2f}\n"
                              f"Data: {data}\n"
                              f"LLM Explanation: {llm_reply}\n"
                              f"---------------------\n")

                        anomaly_record = pd.DataFrame([{
                            "src_port": data.get("src_port"),
                            "dst_port": data.get("dst_port"),
                            "packet_size": data.get("packet_size"),
                            "duration_ms": data.get("duration_ms"),
                            "protocol": data.get("protocol"),
                            "confident_score": score
                        }])

                        header = not os.path.isfile(CSV_FILE_PATH)
                        anomaly_record.to_csv(CSV_FILE_PATH, mode='a', header=header, index=False, encoding='utf-8-sig')

                    else:
                        print(f"Status: Normal (Confidence Score: {score:.2f})\n")

                except json.JSONDecodeError:
                    print(f"Error decoding JSON for line: '{line}'")
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")

except ConnectionRefusedError:
    print(f"Connection refused. Is the server running on {HOST}:{PORT}?")
except KeyboardInterrupt:
    print("\nClient stopped by user.")
except Exception as e:
    print(f"A final error occurred: {e}")
