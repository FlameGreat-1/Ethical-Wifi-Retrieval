import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime

class BehavioralAnalytics:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_path = os.getenv('ML_MODEL_PATH', 'behavioral_analytics_model.pkl')
        self.scaler_path = 'scaler.pkl'
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
        else:
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.scaler = StandardScaler()

    def save_model(self):
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

    def train_model(self, data):
        # Assuming data is a pandas DataFrame with columns: 
        # ['user_id', 'timestamp', 'latitude', 'longitude', 'device_type', 'action']
        features = self._extract_features(data)
        scaled_features = self.scaler.fit_transform(features)
        self.model.fit(scaled_features)
        self.save_model()

    def is_behavior_normal(self, user_id, latitude, longitude, device_type, action):
        current_time = datetime.now()
        features = self._extract_features(pd.DataFrame({
            'user_id': [user_id],
            'timestamp': [current_time],
            'latitude': [latitude],
            'longitude': [longitude],
            'device_type': [device_type],
            'action': [action]
        }))
        scaled_features = self.scaler.transform(features)
        prediction = self.model.predict(scaled_features)
        return prediction[0] == 1  # 1 for normal, -1 for anomaly

    def _extract_features(self, data):
        features = pd.DataFrame()
        features['hour'] = data['timestamp'].dt.hour
        features['day_of_week'] = data['timestamp'].dt.dayofweek
        features['latitude'] = data['latitude']
        features['longitude'] = data['longitude']
        features['device_type'] = pd.Categorical(data['device_type']).codes
        features['action'] = pd.Categorical(data['action']).codes
        
        # Add more complex features
        features['location_cluster'] = self._cluster_locations(data[['latitude', 'longitude']])
        features['time_since_last_action'] = self._time_since_last_action(data)
        
        return features

    def _cluster_locations(self, locations, eps=0.1, min_samples=5):
        from sklearn.cluster import DBSCAN
        clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(locations)
        return clustering.labels_

    def _time_since_last_action(self, data):
        data = data.sort_values('timestamp')
        return data.groupby('user_id')['timestamp'].diff().dt.total_seconds()

# Usage
behavioral_analytics = BehavioralAnalytics()

# Train the model (this would typically be done offline with historical data)
historical_data = pd.read_csv('user_activity_logs.csv')
behavioral_analytics.train_model(historical_data)

# Check if behavior is normal
is_normal = behavioral_analytics.is_behavior_normal(
    user_id='user123',
    latitude=37.7749,
    longitude=-122.4194,
    device_type='android',
    action='retrieve_password'
)
