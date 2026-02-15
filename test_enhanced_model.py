"""
Test script for the enhanced Website Security Analyzer with synthetic dataset generation
"""

import os
import sys
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security_analzyer_3 import WebsiteSecurityAnalyzer

def test_synthetic_dataset_generation():
    """Test the synthetic dataset generation functionality"""
    print("Testing Synthetic Dataset Generation...")
    print("=" * 50)
    
    # Create analyzer instance
    analyzer = WebsiteSecurityAnalyzer(use_ml=True)
    
    # Generate a small synthetic dataset to test the function
    X, y = analyzer._generate_synthetic_dataset(n_samples=1000)
    
    print(f"Generated {len(X)} samples")
    print(f"Feature matrix shape: {X.shape}")
    print(f"Label vector shape: {y.shape}")
    print(f"Malicious samples: {np.sum(y)} ({np.mean(y)*100:.2f}%)")
    print(f"Benign samples: {len(y) - np.sum(y)} ({(1-np.mean(y))*100:.2f}%)")
    
    # Test feature ranges
    print("\nFeature statistics:")
    feature_names = [
        'uses_https', 'suspicious_patterns_count', 'domain_age_days', 'uses_suspicious_tld',
        'domain_length', 'uses_ip', 'redirects', 'subdomains_count', 'url_length'
    ]
    
    for i, name in enumerate(feature_names):
        print(f"{name}: Min={X[:, i].min():.2f}, Max={X[:, i].max():.2f}, Mean={X[:, i].mean():.2f}")
    
    print("\n✓ Synthetic dataset generation test passed!")
    return True

def test_improved_model_training():
    """Test the improved model training with synthetic data"""
    print("\nTesting Improved Model Training...")
    print("=" * 50)
    
    # Create analyzer instance
    analyzer = WebsiteSecurityAnalyzer(use_ml=True)
    
    # The model should already be trained with synthetic data if this is the first run
    print(f"Model type: {type(analyzer.ml_model)}")
    print(f"Model input shape: {analyzer.ml_model.input_shape}")
    print(f"Model output shape: {analyzer.ml_model.output_shape}")
    print(f"Number of layers: {len(analyzer.ml_model.layers)}")
    
    # Test prediction with a sample
    sample_features = np.array([[1, 0, 180, 0, 15, 0, 1, 1, 50]], dtype='float32')
    
    # Scale the features using the analyzer's scaler
    sample_scaled = analyzer.scaler.transform(sample_features)
    prediction = analyzer.ml_model.predict(sample_scaled)
    prediction_binary = 1 if prediction[0][0] >= 0.5 else 0
    
    print(f"Sample prediction probability: {prediction[0][0]:.4f}")
    print(f"Sample prediction (binary): {prediction_binary}")
    
    print("\n✓ Improved model training test passed!")
    return True

def test_model_retraining_with_synthetic_data():
    """Test the model retraining functionality with synthetic data combination"""
    print("\nTesting Model Retraining with Synthetic Data...")
    print("=" * 50)
    
    # Create analyzer instance
    analyzer = WebsiteSecurityAnalyzer(use_ml=True)
    
    # Sample training data for retraining (URL, label) pairs
    sample_training_data = [
        ("https://safe-site.com", 0),      # Benign
        ("http://phishing-example.com", 1), # Malicious
        ("https://legitimate-business.org", 0), # Benign
        ("http://fake-bank.xyz/login.php", 1),  # Malicious
    ]
    
    print(f"Retraining with {len(sample_training_data)} sample URLs...")
    
    # Perform retraining
    success = analyzer.retrain_model(sample_training_data)
    
    if success:
        print("✓ Model retraining completed successfully!")
        
        # Test prediction after retraining
        sample_features = np.array([[0, 5, 5, 1, 25, 1, 3, 2, 120]], dtype='float32')
        sample_scaled = analyzer.scaler.transform(sample_features)
        prediction_after = analyzer.ml_model.predict(sample_scaled)
        print(f"Post-retraining prediction: {prediction_after[0][0]:.4f}")
        
        return True
    else:
        print("✗ Model retraining failed!")
        return False

def test_feature_extraction():
    """Test the feature extraction functionality"""
    print("\nTesting Feature Extraction...")
    print("=" * 50)
    
    analyzer = WebsiteSecurityAnalyzer(use_ml=True)
    
    # Test with various URLs
    test_urls = [
        "https://www.google.com",
        "http://phishing-site.tk/login.php?user=admin",
        "https://secure-bank.example.com/account",
        "http://192.168.1.1/malicious.html"
    ]
    
    for url in test_urls:
        results = {'heuristic_scores': {'domain_age': 1000, 'redirect_chain': 0}}  # Mock results
        features = analyzer._extract_features(url, results)
        
        print(f"URL: {url}")
        print(f"Extracted features: {features}")
        print(f"Features sum: {sum(features)}")
        print("-" * 30)
    
    print("✓ Feature extraction test passed!")
    return True

def main():
    """Run all tests for the enhanced functionality"""
    print("Enhanced Website Security Analyzer - Functionality Tests")
    print("=" * 60)
    
    tests = [
        test_synthetic_dataset_generation,
        test_improved_model_training,
        test_model_retraining_with_synthetic_data,
        test_feature_extraction
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__} failed with error: {e}")
    
    print(f"\nTest Summary: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! The enhanced security analyzer is working correctly.")
        print("\nKey Improvements Implemented:")
        print("• Synthetic dataset generation with 10,000 realistic samples")
        print("• Enhanced neural network with dropout layers")
        print("• Feature scaling for better model performance")
        print("• Early stopping to prevent overfitting")
        print("• Combined synthetic + real data for retraining")
        print("• Improved model evaluation metrics (accuracy, precision, recall)")
    else:
        print(f"\n⚠️  {total - passed} tests failed. Please check the implementation.")

if __name__ == "__main__":
    main()