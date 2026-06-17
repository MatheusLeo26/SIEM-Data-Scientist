import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from datetime import datetime

class SIEMAnalyzer:
    def __init__(self, auth_path="auth_logs.csv", network_path="network_logs.csv"):
        self.auth_path = auth_path
        self.network_path = network_path
        self.auth_df = None
        self.network_df = None
        
    def load_data(self):
        try:
            self.auth_df = pd.read_csv(self.auth_path)
            self.auth_df['timestamp'] = pd.to_datetime(self.auth_df['timestamp'])
            self.auth_df['hour'] = self.auth_df['timestamp'].dt.hour
        except FileNotFoundError:
            print(f"Error: {self.auth_path} not found. Please run generate_data.py first.")
            
        try:
            self.network_df = pd.read_csv(self.network_path)
            self.network_df['timestamp'] = pd.to_datetime(self.network_df['timestamp'])
            self.network_df['hour'] = self.network_df['timestamp'].dt.hour
        except FileNotFoundError:
            print(f"Error: {self.network_path} not found. Please run generate_data.py first.")

    def detect_auth_anomalies(self):
        """
        Detects:
        1. Brute force: More than 5 failed logins within a 5-minute rolling window for a user.
        2. Out-of-hours/unusual logins: Logins between 22:00 and 06:00, or from an unusual country.
        """
        if self.auth_df is None:
            return pd.DataFrame()
            
        df = self.auth_df.copy()
        
        # 1. Brute Force Detection (Rolling Window of 5 minutes)
        # Sort to ensure rolling works correctly
        df = df.sort_values(by=['user', 'timestamp'])
        
        # We set index to timestamp for rolling window
        df_temp = df.set_index('timestamp')
        
        # Group by user, filter by failed, and calculate 5-minute rolling count of failed logins
        df_temp['failed_rolling_5m'] = (
            df_temp['status']
            .eq('failed')
            .groupby(df_temp['user'])
            .rolling('5min')
            .sum()
            .reset_index(level=0, drop=True)
        )
        
        df = df_temp.reset_index()
        
        # Flag as brute force if failed_rolling_5m >= 10
        df['brute_force_flag'] = df['failed_rolling_5m'] >= 10
        
        # 2. Baseline Out-of-hours & Unusual Location Detection
        # Joao normally logs from Brazil between 8 and 18.
        # Carlos, Ana, Maria, Pedro also have normal hours.
        # Let's flag: hour < 6 or hour > 20, or country not in ['Brazil', 'United States'] for regular users,
        # or specifically if country is Romania/Russia etc.
        # Let's write a statistical threshold:
        # A login is an anomaly if the hour is between 22h and 5h, OR if the country is not the user's typical country.
        
        # Find the most frequent (typical) country for each user (baseline)
        typical_countries = df[df['status'] == 'success'].groupby('user')['country'].agg(lambda x: x.value_counts().index[0]).to_dict()
        
        df['typical_country'] = df['user'].map(typical_countries)
        df['unusual_location'] = (df['country'] != df['typical_country']) & (df['status'] == 'success')
        
        # Out of office hours baseline
        df['out_of_hours'] = (df['hour'] < 6) | (df['hour'] > 20)
        
        # Combined anomaly score / flags
        df['anomaly_flag'] = df['brute_force_flag'] | df['unusual_location'] | (df['out_of_hours'] & (df['status'] == 'success'))
        
        return df

    def detect_network_anomalies(self, contamination_rate=0.015):
        """
        Uses K-Means clustering to find outliers.
        Steps:
        1. Select features: bytes_sent, bytes_received, duration_seconds.
        2. Standardize features.
        3. Fit K-Means (e.g. k=3).
        4. Calculate distance of each point to its cluster centroid.
        5. Mark the top % of points with the largest distance as outliers (C2/Exfil).
        """
        if self.network_df is None:
            return pd.DataFrame()
            
        df = self.network_df.copy()
        
        # Features for clustering
        features = ['bytes_sent', 'bytes_received', 'duration_seconds']
        X = df[features]
        
        # Scaling
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # K-Means clustering
        n_clusters = 3
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        df['cluster'] = kmeans.fit_predict(X_scaled)
        
        # Calculate distance to centroids
        centroids = kmeans.cluster_centers_
        distances = []
        for i, label in enumerate(df['cluster']):
            centroid = centroids[label]
            point = X_scaled[i]
            distance = np.linalg.norm(point - centroid)
            distances.append(distance)
            
        df['distance_to_centroid'] = distances
        
        # Define threshold for outliers (e.g., top 1.5% furthest points)
        threshold = np.percentile(distances, 100 * (1 - contamination_rate))
        df['anomaly_flag'] = df['distance_to_centroid'] > threshold
        
        # Map anomaly types based on features for context
        df['anomaly_type'] = 'Normal'
        df.loc[df['anomaly_flag'] & (df['bytes_sent'] > 1_000_000), 'anomaly_type'] = 'Data Exfiltration'
        df.loc[df['anomaly_flag'] & (df['bytes_sent'] < 1000) & (df['duration_seconds'] > 10), 'anomaly_type'] = 'C2 Malware Beaconing'
        df.loc[df['anomaly_flag'] & (df['anomaly_type'] == 'Normal'), 'anomaly_type'] = 'Suspicious Connection'
        
        return df

if __name__ == "__main__":
    analyzer = SIEMAnalyzer()
    analyzer.load_data()
    auth_anom = analyzer.detect_auth_anomalies()
    net_anom = analyzer.detect_network_anomalies()
    print("Authentication anomalies flagged:", auth_anom['anomaly_flag'].sum())
    print("Network anomalies flagged:", net_anom['anomaly_flag'].sum())
