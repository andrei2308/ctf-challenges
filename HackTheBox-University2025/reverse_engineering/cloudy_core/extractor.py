import numpy as np

import tensorflow as tf

interpreter = tf.lite.Interpreter(model_path="snownet_stronger.tflite")
interpreter.allocate_tensors()

def get_raw_bytes(index):
    tensor_details = interpreter.get_tensor_details()[index]
    data = interpreter.get_tensor(tensor_details['index'])
    return data.tobytes()

payload_raw = get_raw_bytes(0)  # serving_default_in_payload
meta_raw = get_raw_bytes(1)     # serving_default_in_meta
const_raw = get_raw_bytes(2)    # arith.constant

print(f"Payload Raw: {payload_raw.hex()}")
print(f"Meta Raw: {meta_raw.hex()}")
print(f"Const Raw: {const_raw.hex()}")
