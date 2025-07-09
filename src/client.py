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

model = joblib.load("C:/Users/OMEN/Documents/GitHub/anomaly-detection-project-tot/src/anomaly_model.joblib")

def pre_process_data(data):
    df = pd.DataFrame([data])
    #TODO 2
    encoded_df = pd.get_dummies(df, columns=['protocol'], drop_first=True)

    if 'protocol_UDP' not in encoded_df.columns:
        encoded_df['protocol_UDP'] = False

    encoded_df = encoded_df[['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']]
    return encoded_df

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    buffer = ""
    print("Client connected to server.\n")

    while True:
        chunk = s.recv(1024).decode()
        if not chunk:
            break
        buffer += chunk

        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            try:
                data = json.loads(line)
                print(f'Data Received:\n{data}\n')

                #TODO 3
                X = pre_process_data(data)
                prediction = model.predict(X)[0]
                if prediction == -1:
                    # Anomaly detected
                    print("🚨 Anomaly Detected! Sending to LLM for explanation...")

                    TOGETHER_API_KEY = os.environ.get("TOGETHER_API_KEY", "")
                    if TOGETHER_API_KEY == "":
                        print("TOGETHER_API_KEY is not set")
                        exit()
                    client = Together(api_key=TOGETHER_API_KEY)
                    user_prompt = (
                        f"Network sensor reading: {data}\n"
                        "Identify the type of anomaly and provide a brief explanation for its possible cause."
                    )
                    messages = [
                        {"role": "system",
                         "content": "You are a cybersecurity assistant that labels and explains network anomalies."},
                        {"role": "user", "content": user_prompt}
                    ]
                    try:
                        response = client.chat.completions.create(
                            model="meta-llama/Meta-Llama-3-70B-Instruct-Turbo",
                            messages=messages,
                            stream=False,
                        )
                        llm_reply = response.choices[0].message.content.strip() if response.choices[
                            0].message.content else "No response from LLM."
                    except Exception as e:
                        llm_reply = f"LLM call failed: {e}"

                    #TODO 4
                    print(f"\n🚨 Anomaly Detected!\nData: {data}\nLLM Explanation: {llm_reply}\n")

                    #csv file
                    anomaly_record = pd.DataFrame([{
                        "src_port": data["src_port"],
                        "dst_port": data["dst_port"],
                        "packet_size": data["packet_size"],
                        "duration_ms": data["duration_ms"],
                        "protocol": data["protocol"],
                    }])
                    # Path to csv file
                    csv_file = "anomalies.csv"
                    # If file exists, appand without header; otherwise, write with header
                    if os.path.isfile(csv_file):
                        anomaly_record.to_csv(csv_file, mode='a', header=False, index=False)
                    else:
                        anomaly_record.to_csv(csv_file, mode='w', header=True, index=False)

                else:
                    print("normal")

            except json.JSONDecodeError:
                print("Error decoding JSON.")
