from flask import Flask, request, jsonify
import pickle
import numpy as np

app = Flask(__name__)

# Load models and preprocessors
with open('palm/models/knn_model.pkl', 'rb') as f:
    knn_model = pickle.load(f)

with open('palm/models/rf_model.pkl', 'rb') as f:
    rf_model = pickle.load(f)

with open('palm/models/pca.pkl', 'rb') as f:
    pca = pickle.load(f)

with open('palm/models/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

@app.route('/predict', methods=['POST'])
def predict():
    # Expect JSON with features array and model type: 'knn' or 'rf'
    data = request.json
    features = np.array(data['features']).reshape(1, -1)

    # Preprocess
    features_scaled = scaler.transform(features)
    features_pca = pca.transform(features_scaled)

    # Select model
    model_type = data.get('model', 'knn').lower()
    if model_type == 'knn':
        prediction = knn_model.predict(features_pca)
    elif model_type == 'rf':
        prediction = rf_model.predict(features_pca)
    else:
        return jsonify({'error': 'Unsupported model type'}), 400

    return jsonify({'prediction': prediction.tolist()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
